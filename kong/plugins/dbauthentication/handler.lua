local access = require "kong.plugins.dbauthentication.access"
local BasePlugin = require "kong.plugins.base_plugin"

local DbAuthHandler = BasePlugin:extend()

function DbAuthHandler:new()
  DbAuthHandler.super.new(self, "dbauthentication")
end

function DbAuthHandler:access(conf)
  DbAuthHandler.super.access(self)
  access.execute(conf)
end

DbAuthHandler.PRIORITY = 1002
DbAuthHandler.VERSION = "0.1.0"

return DbAuthHandler
