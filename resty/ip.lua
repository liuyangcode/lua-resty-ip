local ipairs, tonumber, type = ipairs, tonumber, type
local bit = require("bit")
local rshift = bit.rshift
local band = bit.band
local str_find = string.find
local str_sub = string.sub
local str_gsub = string.gsub
local str_format = string.format
local append = table.insert
local join = table.concat
local str_rep = string.rep
local lrucache
local M = {
    _VERSION = "1.0.0"
}
local function split(str, sepa)
    local rtn = {}
    local start = 1
    local start_pos = 1
    local end_pos = 1
    repeat
        start_pos, end_pos = str_find(str, sepa, start, true)
        if start_pos then
            append(rtn, str_sub(str, start, start_pos - 1))
            start = end_pos + 1
        else
            append(rtn, str_sub(str, start))
        end
    until not start_pos
    return rtn
end
local function copy_bytes(bytes, start_pos, end_pos)
    local new_bytes = {}
    for i = start_pos or 1, end_pos or #bytes do
        append(new_bytes, bytes[i])
    end
    return new_bytes
end
local function table_fill(start, length, val)
    local rtn = {}
    for i = start, length do
        rtn[i] = val
    end
    return rtn
end

local function get_words(long_address)
    local words = split(long_address, ":")
    for index, value in ipairs(words) do
        words[index] = tonumber(value, 16)
    end
    return words
end

local function get_bytes(long_address)
    local bytes = {}
    local chunks = get_words(long_address)
    for _, v in ipairs(chunks) do
        append(bytes, rshift(v, 8))
        append(bytes, band(v, 0xff))
    end
    return bytes
end

local function ipv4_2_ipv6(ipv4)
    local parts = split(ipv4, ".")
    if #parts ~= 4 then
        return nil
    end
    for _, v in ipairs(parts) do
        v = tonumber(v)
        if not v or v <= 0 or v > 255 then
            return nil
        end
    end
    return "0000:0000:0000:0000:0000:0000:" .. str_format("%02x%02x:%02x%02x", parts[1], parts[2], parts[3], parts[4])
end
M.ipv4_2_ipv6 = ipv4_2_ipv6
local function is_ipv4(ipv4)
    return str_find(ipv4, ".", 1, true)
end

local function bytes2ip(bytes_arr)
    local str = {}
    for i, v in ipairs(bytes_arr) do
        if i % 2 ~= 0 then
            append(str, str_format("%02x", v))
        else
            append(str, str_format("%02x:", v))
        end
    end
    return str_sub(join(str, ""), 1, 39)
end

M.bytes2ip = bytes2ip
local function address_from_string(ipstr)
    if lrucache and ipstr then
        local ip = lrucache:get(ipstr)
        if ip then
            return ip
        end
    end
    local chunks = {}
    if is_ipv4(ipstr) then
        ipstr = ipv4_2_ipv6(ipstr)
    end
    if not ipstr then
        return nil, "invalid IP address"
    end
    if str_find(ipstr, "::", 1) then
        local t = split(ipstr, "::")
        local left = t[1]
        local right = t[2]
        for _, leftv in ipairs(split(left, ":")) do
            if leftv ~= "" then
                append(chunks, str_format("%04s", leftv))
            end
        end
        local lefts = #chunks
        for _, rightv in ipairs(split(right or "", ":")) do
            if rightv ~= "" then
                append(chunks, str_format("%04s", rightv))
            end
        end
        for i = 1, 8 - #chunks do
            append(chunks, lefts + 1, str_format("%04s", 0))
        end
    else
        local v = split(ipstr, ":")
        for _, v in ipairs(v) do
            append(chunks, str_format("%04s", v))
        end
    end
    if #chunks ~= 8 then
        return nil, "invalid IP address"
    end
    for index, chunk in ipairs(chunks) do
        local address_long = tonumber(chunk, 16)
        chunks[index] = address_long and str_format("%04x", address_long) or nil
    end
    if #chunks ~= 8 then
        return nil, "invalid IP address"
    end
    local ip = join(chunks, ":")
    if lrucache then
        lrucache:set(ipstr, ip)
    end
    return ip
end

M.address_from_string = address_from_string

local function range_from_string(range_str)
    if lrucache then
        local range_cache = lrucache:get("range" .. range_str)
        if range_cache then
            return range_cache
        end
    end
    local range = split(range_str, "/")
    if #range ~= 2 then
        return nil, "invalid IP range string"
    end
    local networkPrefix = tonumber(range[2])
    if is_ipv4(range[1]) then
        networkPrefix = networkPrefix + 96
    end
    if networkPrefix > 128 or networkPrefix < 1 then
        return nil, "invalid IP range prefix"
    end
    local address = address_from_string(range[1])
    local addressBytes = get_bytes(address)
    local numSameBytes = rshift(networkPrefix, 3)

    local differentBytesStart = 16 == numSameBytes and {} or table_fill(1, 16 - numSameBytes, 0)
    local differentBytesEnd = 16 == numSameBytes and {} or table_fill(1, 16 - numSameBytes, 255)
    local startSameBits = networkPrefix % 8

    if startSameBits ~= 0 then
        local varyingByte = addressBytes[numSameBytes + 1]
        differentBytesStart[1] = band(varyingByte,
                                     tonumber(str_gsub(str_format("%-8s", str_rep(1, startSameBits)), " ", "0"), 2))
        differentBytesEnd[1] = differentBytesStart[1] + tonumber(str_rep("1", 8 - startSameBits), 2)
    end
    local startBytes = copy_bytes(addressBytes, 1, numSameBytes)

    for _, byte in ipairs(differentBytesStart) do
        append(startBytes, byte)
    end
    local endBytes = copy_bytes(addressBytes, 1, numSameBytes)
    for _, byte in ipairs(differentBytesEnd) do
        append(endBytes, byte)
    end
    local range_cache = {bytes2ip(startBytes), bytes2ip(endBytes), networkPrefix}
    if lrucache then
        lrucache:set("range" .. range_str, range_cache)
    end
    return range_cache
end
M.range_from_string = range_from_string
---ip range wether or not contains ip
---@param range string | table
---@param ipstr string
local function range_contains_single_ip(range, ipstr)
    local type_range = type(range)
    local ranges, err
    if type_range == "string" then
        ranges, err = range_from_string(range)
        if not ranges then
            return false, err
        end
    elseif type_range == "table" and #range == 3 then
        ranges = range
    else
        return false, "invalid IP range "
    end

    local address, err = address_from_string(ipstr)

    if not address then
        return false, err
    end
    if address >= ranges[1] and address <= ranges[2] then
        return true
    end
    return false
end

M.range_contains_single_ip = range_contains_single_ip

local function ranges_contains_sigle_ip(ranges, ipstr)
    if type(ranges) ~= "table" then
        return false, "invalid IP ranges"
    end
    local address, err = address_from_string(ipstr)
    if not address then
        return false, err
    end
    repeat
        for _, range in ipairs(ranges) do
            if range_contains_single_ip(range, address) then
                return true
            end
        end
    until true
    return false
end
M.ranges_contains_sigle_ip = ranges_contains_sigle_ip

local function enable_lrucache(size)
    local size = size or 4000 -- Cache the last 4000 IPs (~1MB memory) by default
    local lrucache_obj, err = require("resty.lrucache").new(size)
    if not lrucache_obj then
        return nil, "failed to create the cache: " .. (err or "unknown")
    end
    lrucache = lrucache_obj
    return true
end
M.enable_lrucache = enable_lrucache

return M
