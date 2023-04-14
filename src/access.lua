local _M = {}
local cjson = require "cjson.safe"
local pl_stringx = require "pl.stringx"
local singletons = require "kong.singletons"
local http = require "resty.http"
local str = require "resty.string"
local openssl_digest = require "openssl.digest"
local cipher = require "openssl.cipher"
local aes = cipher.new("AES-128-CBC")
local oidc_error = nil
local salt = nil --16 char alphanumeric
local cookieDomain = nil
local kong = kong

local function dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

local function getUserInfo(access_token, callback_url, conf, authHeader)
    ngx.log(ngx.WARN, "getUserInfo from URL")
    ngx.log(ngx.WARN, conf.user_url)
    ngx.log(ngx.WARN, access_token)

    local httpc = http:new()
    -- local res, err = httpc:request_uri(conf.user_url, {
    --     method = "GET",
    --     ssl_verify = false,
    --     headers = {
    --       ["Authorization"] = "Bearer " .. access_token,
    --     }
    -- })

    local res, err = httpc:request_uri(conf.user_url, {
        method = "POST",
        ssl_verify = false,
        headers = {
        	["Content-Type"] = "application/x-www-form-urlencoded",
         	["Authorization"] = "Bearer " .. access_token,
        },
        body = "client_id=" .. conf.client_id .. "&client_secret=" .. conf.client_secret
    })

    if err then
		ngx.log(ngx.ERR, "Could not retrieve UserInfo from Keycloak: ", err)
	end

	if res then
		ngx.log(ngx.WARN, "HTTP Status: ", res.status)
	end

	-- redirect to auth if user result is invalid not 200
	if not res or res.status ~= 200 then
		if authHeader then
    		oidc_error = {status = ngx.HTTP_UNAUTHORIZED, message = "Hosted domain is not matching"}
    		return kong.response.exit(oidc_error.status, { message = oidc_error.message })
		else
			return redirect_to_auth(conf, callback_url)
		end
	end

	ngx.log(ngx.INFO, "Got userInfo response")

	local userJson = cjson.decode(res.body)
    ngx.log(ngx.WARN, dump(userJson))

	return userJson
end

local function getKongKey(eoauth_token, access_token, callback_url, conf)
    ngx.log(ngx.WARN, "getKongKey")
	-- This will add a 28800 second (8 hour) expiring TTL on this cached value
	-- https://github.com/thibaultcha/lua-resty-mlcache/blob/master/README.md
	local userInfo, err = singletons.cache:get(eoauth_token, { ttl = 28800 }, getUserInfo, access_token, callback_url, conf, false)

	if err then
		ngx.log(ngx.ERR, "Could not retrieve UserInfo: ", err)
		return
	end

	return userInfo
end

function redirect_to_auth( conf, callback_url )
    -- Track the endpoint they wanted access to so we can transparently redirect them back
    if type(ngx.header["Set-Cookie"]) == "table" then
		ngx.header["Set-Cookie"] = { "EOAuthRedirectBack=" .. ngx.var.request_uri .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 120) .. ";Max-Age=120;HttpOnly", unpack(ngx.header["Set-Cookie"]) }
    else
		ngx.header["Set-Cookie"] = { "EOAuthRedirectBack=" .. ngx.var.request_uri .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 120) .. ";Max-Age=120;HttpOnly", ngx.header["Set-Cookie"] }
    end

	-- todo delete the below 2 lines
	ngx.log(ngx.WARN, "set my test cookie")
	ngx.header["Set-Cookie"] = { "MyTestCookie=" .. "testValue" .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 120) .. ";Max-Age=120;HttpOnly", unpack(ngx.header["Set-Cookie"]) }

    -- Redirect to the /oauth endpoint
    local oauth_authorize = nil
    if(not conf.pf_idp_adapter_id or conf.pf_idp_adapter_id == "") then --Standard Auth URL(Something other than ping)
    	oauth_authorize = conf.authorize_url .. "?response_type=code&client_id=" .. conf.client_id .. "&redirect_uri=" .. callback_url .. "&scope=" .. conf.scope
    else --Ping Federate Auth URL
        oauth_authorize = conf.authorize_url .. "?pfidpadapterid=" .. (conf.pf_idp_adapter_id or "") .. "&response_type=code&client_id=" .. conf.client_id .. "&redirect_uri=" .. callback_url .. "&scope=" .. conf.scope
       --oauth_authorize = conf.authorize_url .. "?pfidpadapterid=" .. conf.pf_idp_adapter_id .. "&response_type=code&client_id=" .. conf.client_id .. "&redirect_uri=" .. callback_url .. "&scope=" .. conf.scope .. "&prompt=none"
    end

    return ngx.redirect(oauth_authorize)
end

function encode_token(token, conf)
	return ngx.encode_base64(aes:encrypt(openssl_digest.new("md5"):final(conf.client_secret), salt, true):final(token))
end

function decode_token(token, conf)
    ngx.log(ngx.WARN, "decoding token from cookie")

    local status, token = pcall(function () return aes:decrypt(openssl_digest.new("md5"):final(conf.client_secret), salt, true):final(ngx.decode_base64(token)) end)

    if status then
        return token
    else
        return nil
    end
end

-- Logout Handling
function  handle_logout(encrypted_token, conf)
  --Terminate the Cookie
  if type(ngx.header["Set-Cookie"]) == "table" then
    -- ngx.header["Set-Cookie"] = { "EOAuthToken=;Path=/;Expires=Thu, Jan 01 1970 00:00:00 UTC;Max-Age=0;HttpOnly" .. cookieDomain, unpack(ngx.header["Set-Cookie"]) }
    ngx.header["Set-Cookie"] = { "EOAuthToken=;Path=/;Expires=Thu, Jan 01 1970 00:00:00 UTC;Max-Age=0;HttpOnly", unpack(ngx.header["Set-Cookie"]) }
  else
	-- ngx.header["Set-Cookie"] = { "EOAuthToken=;Path=/;Expires=Thu, Jan 01 1970 00:00:00 UTC;Max-Age=0;HttpOnly" .. cookieDomain, ngx.header["Set-Cookie"] }
	ngx.header["Set-Cookie"] = { "EOAuthToken=;Path=/;Expires=Thu, Jan 01 1970 00:00:00 UTC;Max-Age=0;HttpOnly", ngx.header["Set-Cookie"] }
  end

  if conf.user_info_cache_enabled then
    singletons.cache:invalidate(encrypted_token)
  end

  return kong.response.exit(200)
end

-- Callback Handling
function  handle_callback( conf, callback_url )
    local args = ngx.req.get_uri_args()
    local code = args.code
    local redirect_url

	ngx.log(ngx.WARN, "handle_callback: " .. callback_url)

    if args.redirect_url == nil then
		ngx.log(ngx.WARN, "no redirect_url")
       redirect_url = callback_url
    else
		ngx.log(ngx.WARN, "redirect_url: " .. args.redirect_url)
       redirect_url = args.redirect_url
    end

    if code then
		ngx.log(ngx.WARN, "handle_callback: have code")

        local httpc = http:new()
        local res, err = httpc:request_uri(conf.token_url, {
            method = "POST",
            ssl_verify = false,
            body = "grant_type=authorization_code&client_id=" .. conf.client_id .. "&client_secret=" .. conf.client_secret .. "&code=" .. code .. "&redirect_uri=" .. redirect_url,
            headers = {
              ["Content-Type"] = "application/x-www-form-urlencoded",
            }
        })

        if not res then
			ngx.log(ngx.ERR, "handle_callback: no response from token_url endpoint: " .. err)
            oidc_error = {status = ngx.HTTP_INTERNAL_SERVER_ERROR, message = "Failed to request: " .. err}
            return kong.response.exit(oidc_error.status, { message = oidc_error.message })
        end

        local json = cjson.decode(res.body)
        local access_token = json.access_token
        if not access_token then
			ngx.log(ngx.WARN, "handle_callback: no access_token")
            oidc_error = {status = ngx.HTTP_BAD_REQUEST, message = json.error_description}
            return kong.response.exit(oidc_error.status, { message = oidc_error.message })
        end

		if type(ngx.header["Set-Cookie"]) == "table" then
			ngx.log(ngx.WARN, "update cookie")
			-- ngx.header["Set-Cookie"] = { "EOAuthToken=" .. encode_token(access_token, conf) .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 1800) .. ";Max-Age=1800;HttpOnly" .. cookieDomain, unpack(ngx.header["Set-Cookie"]) }
			ngx.header["Set-Cookie"] = { "EOAuthToken=" .. encode_token(access_token, conf) .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 1800) .. ";Max-Age=1800;HttpOnly", unpack(ngx.header["Set-Cookie"]) }
        else
			ngx.log(ngx.WARN, "set cookie")
			-- ngx.header["Set-Cookie"] = { "EOAuthToken=" .. encode_token(access_token, conf) .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 1800) .. ";Max-Age=1800;HttpOnly" .. cookieDomain, ngx.header["Set-Cookie"] }
			ngx.header["Set-Cookie"] = { "EOAuthToken=" .. encode_token(access_token, conf) .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 1800) .. ";Max-Age=1800;HttpOnly", ngx.header["Set-Cookie"] }
        end

		-- todo delete the below line
		ngx.log(ngx.WARN, "set my test cookie 2")
		ngx.header["Set-Cookie"] = { "MyTestCookie2=" .. "testValue2" .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 120) .. ";Max-Age=120;HttpOnly", unpack(ngx.header["Set-Cookie"]) }

        -- Support redirection back to Kong if necessary
        local redirect_back = ngx.var.cookie_EOAuthRedirectBack

        if redirect_back then
			ngx.log(ngx.WARN, "redirect back: " .. redirect_back)
            return ngx.redirect(redirect_back) --Should always land here if no custom Loggedin page defined!
        end

		--Support redirection back to Application Loggedin Dashboard for subsequent transactions
		if conf.app_login_redirect_url ~= "" then
			ngx.log(ngx.WARN, "redirecting to app_login_redirect_url: " .. conf.app_login_redirect_url)
		   return ngx.redirect(conf.app_login_redirect_url)
		end

		return
    else
		ngx.log(ngx.WARN, "handle_callback: no code")
        oidc_error = {status = ngx.HTTP_UNAUTHORIZED, message = "User has denied access to the resources"}
        return kong.response.exit(oidc_error.status, { message = oidc_error.message })
    end
end

function _M.run(conf)
	local path_prefix = ""
	local callback_url = ""
	cookieDomain = ";Domain=" .. conf.cookie_domain
	salt = conf.salt

	--Fix for /api/team/POC/oidc/v1/service/oauth2/callback?code=*******
	if ngx.var.request_uri:find('?') then
	   path_prefix = ngx.var.request_uri:sub(1, ngx.var.request_uri:find('?') -1)
	else
	   path_prefix = ngx.var.request_uri
	end

	local scheme = ngx.var.scheme
	if conf.force_ssl_for_redirect then
		ngx.log(ngx.WARN, "conf.force_ssl_for_redirect: true")
		scheme = "https"
	end

	if pl_stringx.endswith(path_prefix, "/") then
	  ngx.log(ngx.WARN, "ends with /")
	  path_prefix = path_prefix:sub(1, path_prefix:len() - 1)
	  callback_url = scheme .. "://" .. ngx.var.host .. path_prefix .. "/oauth2/callback"
	elseif pl_stringx.endswith(path_prefix, "/oauth2/callback") then --We are in the callback of our proxy
	  ngx.log(ngx.WARN, "ends with /oauth2/callback")
	  callback_url = scheme .. "://" .. ngx.var.host .. path_prefix
	  handle_callback(conf, callback_url)
	else
	  ngx.log(ngx.WARN, "set callback_url with oauth2")
	  callback_url = scheme .. "://" .. ngx.var.host .. path_prefix .. "/oauth2/callback"
	end

	ngx.log(ngx.WARN, "callback_url: " .. callback_url)

	local authHeader = false
    local access_token = ngx.req.get_headers()["Authorization"]
    if access_token then
    	authHeader = true
	    ngx.log(ngx.INFO, "Access Token in Header")
        access_token = pl_stringx.replace(access_token, "Bearer ", "", 1)

	    ngx.log(ngx.INFO, "Auth Header No Cookie so getUserInfo")
		local json = getUserInfo(access_token, callback_url, conf, true)

		if json then
		    ngx.log(ngx.INFO, "Got json")
	    	if conf.hosted_domain and conf.email_key then
		    	if conf.hosted_domain ~= "" and conf.email_key ~= "" then
					if not pl_stringx.endswith(json[conf.email_key], conf.hosted_domain) then
					    ngx.log(ngx.WARN, "Hosted domain is not matching")
					    ngx.log(ngx.WARN, conf.hosted_domain)
			    		oidc_error = {status = ngx.HTTP_UNAUTHORIZED, message = "Hosted domain is not matching"}
			    		return kong.response.exit(oidc_error.status, { message = oidc_error.message })
					end
		    	end
		    end

		    for i, key in ipairs(conf.user_keys) do
			    -- ngx.log(ngx.WARN, "1 set header: " .. key .. ", " .. (json[key] or ""))
				ngx.header["X-Oauth-".. key] = json[key]
				ngx.req.set_header("X-Oauth-".. key, json[key])
	    	end
	    	ngx.header["X-Oauth-Token"] = access_token
		else
		    ngx.log(ngx.ERR, "500 return")
		    ngx.log(ngx.ERR, err)
	    	return kong.response.exit(500, { message = err })
		end
    else
        ngx.log(ngx.WARN, "No access token was found in the Authorization bearer header")

        local encrypted_token = ngx.var.cookie_EOAuthToken
        if encrypted_token then
	        ngx.log(ngx.WARN, "have encrypted_token")
            access_token = decode_token(encrypted_token, conf)
        end


		-- check if we are authenticated already
		if access_token then
	        ngx.log(ngx.WARN, "have access_token")

		    --They had a valid EOAuthToken so its safe to process a proper logout now.
		    if pl_stringx.endswith(path_prefix, "/logout") then
			    ngx.log(ngx.WARN, "logging out")
		    	return handle_logout(encrypted_token, conf)
		    end

		    --Update the Cookie to increase longevity for 30 more minutes if active proxying
		    if type(ngx.header["Set-Cookie"]) == "table" then
				-- ngx.header["Set-Cookie"] = { "EOAuthToken=" .. encode_token(access_token, conf) .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 1800) .. ";Max-Age=1800;HttpOnly" .. cookieDomain, unpack(ngx.header["Set-Cookie"]) }
				ngx.header["Set-Cookie"] = { "EOAuthToken=" .. encode_token(access_token, conf) .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 1800) .. ";Max-Age=1800;HttpOnly", unpack(ngx.header["Set-Cookie"]) }
		    else
				-- ngx.header["Set-Cookie"] = { "EOAuthToken=" .. encode_token(access_token, conf) .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 1800) .. ";Max-Age=1800;HttpOnly" .. cookieDomain, ngx.header["Set-Cookie"] }
				ngx.header["Set-Cookie"] = { "EOAuthToken=" .. encode_token(access_token, conf) .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 1800) .. ";Max-Age=1800;HttpOnly", ngx.header["Set-Cookie"] }
		    end

		     --CACHE LOGIC - Check boolean and then if EOAUTH has existing key -> userInfo value
		    if conf.user_info_cache_enabled then
			    ngx.log(ngx.WARN, "user_info_cache_enabled = true")
				local userInfo = getKongKey(encrypted_token, access_token, callback_url, conf)
				if userInfo then
					for i, key in ipairs(conf.user_keys) do
					    -- ngx.log(ngx.WARN, "2 set header: " .. key .. ", " .. (userInfo[key] or ""))
				    	ngx.header["X-Oauth-".. key] = userInfo[key]
				    	ngx.req.set_header("X-Oauth-".. key, userInfo[key])
					end
				    ngx.header["X-Oauth-Token"] = access_token
					return
				end
		    end
		    -- END OF NEW CACHE LOGIC --

		    -- Get user info
		    if not ngx.var.cookie_EOAuthUserInfo then
			    ngx.log(ngx.WARN, "No Cookie so getUserInfo")
				local json = getUserInfo(access_token, callback_url, conf, false)

				if json then
				    ngx.log(ngx.WARN, "Got json")
			    	if conf.hosted_domain and conf.email_key then
				    	if conf.hosted_domain ~= "" and conf.email_key ~= "" then
							if not pl_stringx.endswith(json[conf.email_key], conf.hosted_domain) then
							    ngx.log(ngx.WARN, "Hosted domain is not matching")
							    ngx.log(ngx.WARN, conf.hosted_domain)
					    		oidc_error = {status = ngx.HTTP_UNAUTHORIZED, message = "Hosted domain is not matching"}
					    		return kong.response.exit(oidc_error.status, { message = oidc_error.message })
							end
				    	end
				    end

				    for i, key in ipairs(conf.user_keys) do
					    -- ngx.log(ngx.WARN, "3 set header: " .. key .. ", " .. (json[key] or ""))
						ngx.header["X-Oauth-".. key] = json[key]
						ngx.req.set_header("X-Oauth-".. key, json[key])
			    	end
			    	ngx.header["X-Oauth-Token"] = access_token

			    	if type(ngx.header["Set-Cookie"]) == "table" then
						ngx.header["Set-Cookie"] = { "EOAuthUserInfo=0;Path=/;Expires=" .. ngx.cookie_time(ngx.time() + conf.user_info_periodic_check) .. ";Max-Age=" .. conf.user_info_periodic_check .. ";HttpOnly", unpack(ngx.header["Set-Cookie"]) }
			    	else
						ngx.header["Set-Cookie"] = { "EOAuthUserInfo=0;Path=/;Expires=" .. ngx.cookie_time(ngx.time() + conf.user_info_periodic_check) .. ";Max-Age=" .. conf.user_info_periodic_check .. ";HttpOnly", ngx.header["Set-Cookie"] }
			    	end

				else
				    ngx.log(ngx.ERR, "500 return")
				    ngx.log(ngx.ERR, err)
			    	return kong.response.exit(500, { message = err })
				end
		    end
		else
	        ngx.log(ngx.WARN, "no access_token")
		    return redirect_to_auth(conf, callback_url)
		end
	end
end

return _M
