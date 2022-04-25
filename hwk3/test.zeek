# zeek script to detect proxy source IP

# a global table to record source IP with its user-agents
global sip_ua_table: table[addr] of set[string];

event http_header(C: connection, is_orig: bool, original_name: string, name: string, value: string)
{
    # user-agent
    local user_agent = to_lower(C$http$user_agent);
    # source IP
    local sip: addr = C$id$orig_h;
    # a set to record user-agent
    local ua_set: set[string];

    if (sip !in sip_ua_table)
    {
        add ua_set[user_agent];
    }
    else
    {
        ua_set = sip_ua_table[sip];
        add ua_set[user_agent];
    }
    # update table
    sip_ua_table[sip] = ua_set;
}

event zeek_done()
{
   for (sip, ua_set in sip_ua_table)
   {
       # if a source IP is related to three different user-agents or more
       if (|ua_set| >= 3)
       {
           print fmt("%s is a proxy", sip);
       }
   }
}
