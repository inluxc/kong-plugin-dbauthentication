package = "kong-plugin-dbauthentication"
version = "0.1.0-1"               -- TODO: renumber, must match the info in the filename of this rockspec!
-- The version '0.1.0' is the source code version, the trailing '1' is the version of this rockspec.
-- whenever the source version changes, the rockspec should be reset to 1. The rockspec version is only
-- updated (incremented) when this file changes, but the source remains the same.

local pluginName = "dbauthentication"

supported_platforms = {"linux", "macosx"}
source = {
  -- these are initially not required to make it work
  url = "git://github.com/Mashape/kong_plugin", -- TODO change this
  tag = "0.1.0"
}

description = {
  summary = "This plugin is inspired from the official ldap auth plugin, except it connects to a database to verify credentials",
  homepage = "http://getkong.org",  -- TODO change this
  license = "MIT"
}

dependencies = {
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins."..pluginName..".handler"] = "kong/plugins/"..pluginName.."/handler.lua",
    ["kong.plugins."..pluginName..".schema"] = "kong/plugins/"..pluginName.."/schema.lua",
  }
}
