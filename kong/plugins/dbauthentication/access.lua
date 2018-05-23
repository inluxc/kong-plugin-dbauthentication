local responses = require "kong.tools.responses"
local constants = require "kong.constants"
local singletons = require "kong.singletons"
local mysql = require "resty.mysql"

local match = string.match
local lower = string.lower
local find = string.find
local sub = string.sub
local ngx_log = ngx.log
local request = ngx.req
local ngx_error = ngx.ERR
local ngx_debug = ngx.DEBUG
local ngx_warn = ngx.WARN
local decode_base64 = ngx.decode_base64
local ngx_socket_tcp = ngx.socket.tcp
local ngx_set_header = ngx.req.set_header
local tostring =  tostring

local AUTHORIZATION = "authorization"
local PROXY_AUTHORIZATION = "proxy-authorization"

local _M = {}

local function retrieve_credentials(authorization_header_value, conf)
  local username, password
  if authorization_header_value then
    local s, e = find(lower(authorization_header_value), "^%s*" .. lower(conf.header_type) .. "%s+")
    if s == 1 then
      local cred = sub(authorization_header_value, e + 1)
      local decoded_cred = decode_base64(cred)
      username, password = match(decoded_cred, "([^\n]+):([^\n]+)")
    end
  end
  return username, password
end

local function db_authenticate(given_username, given_password, conf)
  local is_authenticated
  local err, suppressed_err, ok


-- to prevent sql injections
--local name = ngx.unescape_uri(ngx.var.arg_name)
--local quoted_name = ngx.quote_sql_str(name)
--local sql = "select * from users where name = " .. quoted_name



--  local sock = ngx_socket_tcp()
--  sock:settimeout(conf.timeout)
--  ok, err = sock:connect(conf.db_host, conf.db_port)
--  if not ok then
--    ngx_log(ngx_error, "[dbauthenticate] failed to connect to " .. conf.db_host .. ":" .. tostring(conf.db_port) .. ": ", err)
--    return nil, err
--  end
--
--  if conf.start_tls then
--    local success, err = mysql.start_tls(sock)
--    if not success then
--      return false, err
--    end
--    local _, err = sock:sslhandshake(true, conf.db_host, conf.verify_db_host)
--    if err ~= nil then
--      return false, "failed to do SSL handshake with " .. conf.db_host .. ":" .. tostring(conf.db_port) .. ": " .. err
--    end
--  end
--
--  is_authenticated, err = mysql.bind_request(sock, who, given_password)
--
--  ok, suppressed_err = sock:setkeepalive(conf.keepalive)


  local db, err = mysql:new()
  if not db then
    ngx_log(ngx_warn, "[dbauthenticate] failed to instantiate mysql: ", err)
    return is_authenticated, err
  end

  db:set_timeout(1000) -- 1 sec

  -- or connect to a unix domain socket file listened
  -- by a mysql server:
  --     local ok, err, errcode, sqlstate =
  --           db:connect{
  --              path = "/path/to/mysql.sock",
  --              database = "ngx_test",
  --              user = "ngx_test",
  --              password = "ngx_test" }

  local ok, err, errcode, sqlstate = db:connect{
    host = conf.db_host,
    port = conf.db_port,
    database = conf.db_name,
    user = conf.db_user,
    password = conf.db_passwd,
    charset = "utf8",
    max_packet_size = 1024 * 1024,
  }

  if not ok then
    ngx_log(ngx_warn, "[dbauthenticate] failed to connect: ", err, ": ", errcode, " ", sqlstate)
    return is_authenticated, err
  end

  ngx_log(ngx_debug, "[dbauthenticate] connected to mysql.")

--  local res, err, errcode, sqlstate = db:query("drop table if exists cats")
--  if not res then
--    ngx.say("bad result: ", err, ": ", errcode, ": ", sqlstate, ".")
--    return
--  end
--
--  res, err, errcode, sqlstate = db:query("create table cats "
--          .. "(id serial primary key, "
--          .. "name varchar(5))")
--  if not res then
--    ngx.say("bad result: ", err, ": ", errcode, ": ", sqlstate, ".")
--    return
--  end
--
--  ngx.say("table cats created.")
--
--  res, err, errcode, sqlstate =
--  db:query("insert into cats (name) "
--          .. "values (\'Bob\'),(\'\'),(null)")
--  if not res then
--    ngx.say("bad result: ", err, ": ", errcode, ": ", sqlstate, ".")
--    return
--  end
--
--  ngx.say(res.affected_rows, " rows inserted into table cats ",
--    "(last insert id: ", res.insert_id, ")")

  -- run a select query, expected about 10 rows in
  -- the result set:
  local query = "select * from " .. conf.db_user_table .. " where " .. conf.db_username_column .. "=\'" .. given_username .. "\' and " .. conf.db_passwd_column .. "=\'" .. given_password .. "\'"
  ngx_log(ngx.INFO, "pwd : _____" .. given_password .. "____")
  local res, err, errcode, sqlstate = db:query(query, 10)
  local cjson = require "cjson"
  ngx_log(ngx.INFO, "[dbauthenticate] result '", cjson.encode(res), "'")
  ngx_log(ngx.INFO, "[dbauthenticate] query __ ", query, " __")
  if not res then
    ngx_log(ngx_warn, "[dbauthenticate] bad result: ", err, ": ", errcode, ": ", sqlstate, ".")
    is_authenticated = false
  else
    if next(res) == nil then
      ngx_log(ngx.INFO, "[dbauthenticate] login failed with username '", given_username, "'")
      is_authenticated = false
    else
      ngx_log(ngx.DEBUG, "[dbauthenticate] login succeed with username '", given_username, "'")
      is_authenticated = true
    end
  end


  -- put it into the connection pool of size 100,
  -- with 10 seconds max idle timeout
  local ok, err = db:set_keepalive(10000, 100)
  if not ok then
    ngx_log(ngx_warn, "[dbauthenticate] failed to set keepalive: ", err)
    return is_authenticated, err
  end

  -- or just close the connection right away:
  -- local ok, err = db:close()
  -- if not ok then
  --     ngx.say("failed to close: ", err)
  --     return
  -- end


  return is_authenticated, err
end

local function load_credential(given_username, given_password, conf)
  ngx_log(ngx_debug, "[dbauthenticate] authenticating user against LDAP server: " .. conf.db_host .. ":" .. conf.db_port)

  local ok, err = db_authenticate(given_username, given_password, conf)
  if err ~= nil then
    ngx_log(ngx_error, err)
  end

  if ok == nil then
    return nil
  end
  if ok == false then
    return false
  end
  return {username = given_username, password = given_password}
end

local function authenticate(conf, given_credentials)
  local given_username, given_password = retrieve_credentials(given_credentials, conf)
  if given_username == nil then
    return false
  end

  local cache_key = "dbauthenticate_cache:" .. ngx.ctx.api.id .. ":" .. given_username
  local credential, err = singletons.cache:get(cache_key, {
    ttl = conf.cache_ttl,
    neg_ttl = conf.cache_ttl,
  }, load_credential, given_username, given_password, conf)
  if err or credential == nil then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
  end

  return credential and credential.password == given_password, credential
end

local function load_consumer(consumer_id, anonymous)
  local result, err = singletons.dao.consumers:find { id = consumer_id }
  if not result then
    if anonymous and not err then
      err = 'anonymous consumer "' .. consumer_id .. '" not found'
    end
    return nil, err
  end
  return result
end

local function set_consumer(consumer, credential)

  if consumer then
    -- this can only be the Anonymous user in this case
    ngx_set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
    ngx_set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
    ngx_set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
    ngx_set_header(constants.HEADERS.ANONYMOUS, true)
    ngx.ctx.authenticated_consumer = consumer
    return
  end

  -- here we have been authenticated by db
  ngx_set_header(constants.HEADERS.CREDENTIAL_USERNAME, credential.username)
  ngx.ctx.authenticated_credential = credential

  -- in case of auth plugins concatenation, remove remnants of anonymous
  ngx.ctx.authenticated_consumer = nil
  ngx_set_header(constants.HEADERS.ANONYMOUS, nil)
  ngx_set_header(constants.HEADERS.CONSUMER_ID, nil)
  ngx_set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, nil)
  ngx_set_header(constants.HEADERS.CONSUMER_USERNAME, nil)

end

local function do_authentication(conf)
  local headers = request.get_headers()
  local authorization_value = headers[AUTHORIZATION]
  local proxy_authorization_value = headers[PROXY_AUTHORIZATION]

  -- If both headers are missing, return 401
  if not (authorization_value or proxy_authorization_value) then
    ngx.header["WWW-Authenticate"] = 'LDAP realm="kong"'
    return false, {status = 401}
  end

  local is_authorized, credential = authenticate(conf, proxy_authorization_value)
  if not is_authorized then
    is_authorized, credential = authenticate(conf, authorization_value)
  end

  if not is_authorized then
    return false, {status = 403, message = "Invalid authentication credentials"}
  end

  if conf.hide_credentials then
    request.clear_header(AUTHORIZATION)
    request.clear_header(PROXY_AUTHORIZATION)
  end

  set_consumer(nil, credential)

  return true
end


function _M.execute(conf)

  if ngx.ctx.authenticated_credential and conf.anonymous ~= "" then
    -- we're already authenticated, and we're configured for using anonymous,
    -- hence we're in a logical OR between auth methods and we're already done.
    return
  end

  local ok, err = do_authentication(conf)
  if not ok then
    if conf.anonymous ~= "" then

      -- get anonymous user
      local consumer_cache_key = singletons.dao.consumers:cache_key(conf.anonymous)
      local consumer, err      = singletons.cache:get(consumer_cache_key, nil,
                                                      load_consumer,
                                                      conf.anonymous, true)
      if err then
        responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
      end
      set_consumer(consumer, nil)
    else
      return responses.send(err.status, err.message)
    end
  end
end


return _M
