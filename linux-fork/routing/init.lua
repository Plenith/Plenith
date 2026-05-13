local geo = ngx.shared.plenith_geo
local rep = ngx.shared.plenith_rep
local rates = ngx.shared.plenith_rates

-- Simulate the Windows host being a known-bad source for this test
geo:set("geo:172.18.0.1", "RU")
rep:set("rep:172.18.0.1", "92")
rep:set("tor:172.18.0.1", "1")
rates:set("fail:172.18.0.1", "12")

ngx.log(ngx.NOTICE, "[plenith] init.lua: HIGH-RISK SCENARIO seeded for 172.18.0.1")
