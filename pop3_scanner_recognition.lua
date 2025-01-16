local COUNT = 30 -- Number of observations required for a match
local SECONDS = 120 -- Number of seconds in which the observations are to be seen
local CLEANUP = 120 -- Number of seconds inbetween cleanups to reduce memory usage and keep speed adequate

local scanner_table = {} -- Maps IP addresses to a sequence of timestamps
local last_cleanup = nil

function init (args)
    -- Required function by Suricata Syntax, but not used for this script.
    local needs = {}

    return needs
end

function cleanup()
    -- Cleanup for every IP address
    for j, w in ipairs(scanner_table) do
        new_sub_table = {}
        hits = 0
        for i,v in ipairs(scanner_table[srcip]) do
            if v > last_time - SECONDS then
                table.insert(new_sub_table, v)
                hits = hits + 1
            end
        end

        if hits == 0 then
            scanner_table[srcip] = nil
        else
            scanner_table[srcip] = new_sub_table
        end
    end
end

function match(args)
    -- Retrieve srcip and determine if it is a scanning IP
    ipver, srcip, dstip, proto, sp, dp = SCPacketTuple()

    -- If the IP has not yet been observed, create an empty table
    if scanner_table[srcip] == nil then
        scanner_table[srcip] = {}
    end

    -- Determine timestamp of new observation and add it to the sequence
    last_time = os.time()
    table.insert(scanner_table[srcip], last_time)

    -- Count the number of observations within the SECONDS time window and prepare cleanup for this IP
    new_sub_table = {}
    hits = 0
    for i,v in ipairs(scanner_table[srcip]) do
        if v > last_time - SECONDS then
            table.insert(new_sub_table, v)
            hits = hits + 1
        end
    end

    -- Every CLEANUP seconds, we should iterate over all IP addresses to perform cleanup and remove outdated entries
    if last_cleanup == nil or last_cleanup + CLEANUP < last_time then
		if last_cleanup ~= nil then
            cleanup()
	    end
        last_cleanup = last_time
    else
	    -- Even if CLEANUP has not yet been exceeded, we can easily clean up the currently investigated IP sequence
        scanner_table[srcip] = new_sub_table
    end

    -- Return a positive match if COUNT observations are made within SECONDS seconds
    if hits >= COUNT then
        return 1
    end

    -- Return a negative match otherwise
    return 0
end