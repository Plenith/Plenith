-- Plenith identity proxy + risk-engine routing module.
--
-- Drop this under /etc/nginx/lua/ and reference from your stream block:
--
--     stream {
--         lua_package_path "/etc/nginx/lua/?.lua;;";
--         init_by_lua_file /etc/nginx/lua/init.lua;
--
--         upstream real_prod  { server 10.10.5.10:22; }
--         upstream mfa_relay  { server 10.10.5.11:22; }
--         upstream plenith { server 10.10.99.10:2222; }
--
--         server {
--             listen 22;
--             preread_by_lua_file /etc/nginx/lua/score_and_route.lua;
--             proxy_pass $upstream_pool;
--         }
--     }
--
-- The companion init.lua should set up shared dictionaries:
--     lua_shared_dict plenith_geo  10m;
--     lua_shared_dict plenith_rep  10m;
--     lua_shared_dict plenith_rates 10m;
--
-- This module reads a number of signals about the inbound connection,
-- computes a weighted score, and picks one of three upstream pools.
-- High scores route to Plenith. Borderline routes to MFA. Low routes
-- to real production.
--
-- Score range = roughly 0–10. Cutoffs:
--   < 3   real prod
--   3-6   MFA challenge
--   >= 6  Plenith decoy
--
-- All branches default to MFA on internal failure (fail-safe).

local ngx = ngx
local string = string
local tonumber = tonumber

-- ---------------------------------------------------------------------------
-- Configuration weights. Tune per organization.
-- ---------------------------------------------------------------------------
local WEIGHT = {
    geo_mismatch     = 1,   -- unexpected country for this user
    geo_high_risk    = 2,   -- known-bad country
    novel_ja3        = 2,   -- new client fingerprint
    odd_hours        = 1,   -- well outside the user's normal window
    breached_pw      = 3,   -- HIBP indicates the password is known-leaked
    bad_reputation   = 3,   -- AbuseIPDB / TI feed confidence ≥ 75%
    tor_exit         = 2,
    commercial_vpn   = 1,
    concurrent_geo   = 1,   -- same user, different geo, overlapping time
    repeated_auth_fail = 1, -- per failure beyond threshold
}

local THRESHOLD_DECOY = 6
local THRESHOLD_MFA   = 3

-- ---------------------------------------------------------------------------
-- MFA step-up: decision file handoff (§4.3).
--
-- The MFA gateway (linux-fork/mfa/mfa_gateway.py) writes one of these on
-- the way out of a challenge:
--     /mnt/state/mfa/<source_ip>.pass
--     /mnt/state/mfa/<source_ip>.fail
-- A `.pass` makes the user's NEXT connection bypass scoring entirely and
-- route to real-prod (for the configured TTL). A `.fail` silently routes
-- them to Plenith — they think they're going to prod, they're not.
-- Either way, the file is consumed on read so a single decision authorizes
-- exactly one inbound session.
-- ---------------------------------------------------------------------------
local MFA_STATE_DIR = "/mnt/state/mfa"
local MFA_TTL_SECONDS = 300   -- 5 minute grace


-- ---------------------------------------------------------------------------
-- Signal getters. In production these talk to real services / caches.
-- The stubs here read from preconfigured shared dicts populated elsewhere.
-- ---------------------------------------------------------------------------

local function get_remote_ip()
    return ngx.var.remote_addr or "0.0.0.0"
end

local function get_geo(ip)
    -- Look up country from MaxMind-populated shared dict.
    local geo = ngx.shared.plenith_geo
    return geo and geo:get("geo:" .. ip) or "??"
end

local function get_reputation(ip)
    local rep = ngx.shared.plenith_rep
    if not rep then return 0 end
    return tonumber(rep:get("rep:" .. ip)) or 0  -- 0..100
end

local function get_recent_failures(ip)
    local rates = ngx.shared.plenith_rates
    if not rates then return 0 end
    return tonumber(rates:get("fail:" .. ip)) or 0
end

local function is_tor_exit(ip)
    local rep = ngx.shared.plenith_rep
    return rep and rep:get("tor:" .. ip) and true or false
end

-- ---------------------------------------------------------------------------
-- MFA decision file consumption. Returns "pass" / "fail" / nil.
-- We parse the simple `key=value\n` body the gateway writes so we can
-- check `ts=` for freshness without needing luafilesystem.
-- ---------------------------------------------------------------------------

local function _parse_ts(body)
    -- Body looks like "ip=...\ndecision=...\nts=12345\n". Extract ts.
    local ts = string.match(body or "", "ts=(%d+)")
    return tonumber(ts)
end

local function _consume_decision(ip, decision)
    local path = MFA_STATE_DIR .. "/" .. ip .. "." .. decision
    local f = io.open(path, "r")
    if not f then return nil end
    local body = f:read("*a")
    f:close()
    local ts = _parse_ts(body)
    if not ts then
        -- Malformed; treat as missing. Don't delete — operator can inspect.
        return nil
    end
    if (os.time() - ts) > MFA_TTL_SECONDS then
        os.remove(path)
        return nil
    end
    -- Consume — single decision authorizes exactly one session.
    os.remove(path)
    return decision
end

local function check_mfa_decision(ip)
    -- "pass" wins if both exist (defensive — shouldn't happen since the
    -- gateway clears old decisions before writing the new one).
    local pass = _consume_decision(ip, "pass")
    if pass then return "pass" end
    local fail = _consume_decision(ip, "fail")
    if fail then return "fail" end
    return nil
end

-- ---------------------------------------------------------------------------
-- Score the inbound connection.
-- ---------------------------------------------------------------------------

local function compute_score(ctx)
    local score = 0
    local reasons = {}

    -- 1. Geo
    if ctx.geo == "RU" or ctx.geo == "KP" or ctx.geo == "IR" then
        score = score + WEIGHT.geo_high_risk
        reasons[#reasons + 1] = "geo_high_risk=" .. ctx.geo
    elseif ctx.geo ~= "US" and ctx.geo ~= "CA" and ctx.geo ~= "GB" and ctx.geo ~= "??" then
        -- Adjust this allow-list per your org's geo footprint.
        score = score + WEIGHT.geo_mismatch
        reasons[#reasons + 1] = "geo_mismatch=" .. ctx.geo
    end

    -- 2. Reputation
    if ctx.reputation >= 75 then
        score = score + WEIGHT.bad_reputation
        reasons[#reasons + 1] = "bad_rep=" .. ctx.reputation
    end

    -- 3. Tor / VPN
    if ctx.tor then
        score = score + WEIGHT.tor_exit
        reasons[#reasons + 1] = "tor_exit"
    end

    -- 4. Recent auth failures from this IP
    if ctx.recent_fails > 5 then
        local extra = ctx.recent_fails - 5
        score = score + math.min(extra, 3) * WEIGHT.repeated_auth_fail
        reasons[#reasons + 1] = "auth_fails=" .. ctx.recent_fails
    end

    -- 5. Time of day. Stub: rough proxy — any request between 02:00 and
    --    05:00 UTC counts as odd hours.
    local hour = tonumber(os.date("!%H"))
    if hour and (hour >= 2 and hour < 5) then
        score = score + WEIGHT.odd_hours
        reasons[#reasons + 1] = "odd_hours=" .. hour
    end

    -- 6. Novel JA3 / SSH banner (not implemented in this stub).
    -- See ngx_stream_ssl_preread_module for hooks.

    return score, reasons
end

-- ---------------------------------------------------------------------------
-- Decide upstream pool.
-- ---------------------------------------------------------------------------

local function pick_upstream(score)
    if score >= THRESHOLD_DECOY then return "plenith" end
    if score >= THRESHOLD_MFA   then return "mfa_relay"  end
    return "real_prod"
end

-- ---------------------------------------------------------------------------
-- Main: assemble the context, score, set ngx.var.plenith_pool.
-- ---------------------------------------------------------------------------

local function main()
    local ok, err = pcall(function()
        local ip = get_remote_ip()

        -- 0. Check for a pending MFA decision FIRST. A recent .pass or
        --    .fail short-circuits the entire scoring pipeline — that's the
        --    whole point of the step-up flow.
        local mfa = check_mfa_decision(ip)
        if mfa == "pass" then
            ngx.var.plenith_pool = "real_prod"
            ngx.log(ngx.NOTICE, string.format(
                "[plenith] route ip=%s pool=real_prod (mfa-pass consumed)", ip
            ))
            return
        elseif mfa == "fail" then
            ngx.var.plenith_pool = "plenith"
            ngx.log(ngx.NOTICE, string.format(
                "[plenith] route ip=%s pool=plenith (mfa-fail consumed - silent redirect)", ip
            ))
            return
        end

        -- 1. Normal scoring path.
        local ctx = {
            ip          = ip,
            geo         = get_geo(ip),
            reputation  = get_reputation(ip),
            tor         = is_tor_exit(ip),
            recent_fails = get_recent_failures(ip),
        }
        local score, reasons = compute_score(ctx)
        local pool = pick_upstream(score)

        ngx.var.plenith_pool = pool

        ngx.log(ngx.NOTICE, string.format(
            "[plenith] route ip=%s geo=%s rep=%d tor=%s fails=%d score=%d pool=%s reasons=%s",
            ctx.ip, ctx.geo, ctx.reputation, tostring(ctx.tor),
            ctx.recent_fails, score, pool, table.concat(reasons, ",")
        ))
    end)
    if not ok then
        -- Fail-safe: any error in the scoring pipeline routes to MFA so we
        -- never silent-route to decoy on internal failure.
        ngx.var.plenith_pool = "mfa_relay"
        ngx.log(ngx.ERR, "[plenith] scoring failed, routing to MFA: " .. tostring(err))
    end
end

main()
