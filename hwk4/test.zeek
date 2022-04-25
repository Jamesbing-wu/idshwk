# zeek script to make 404 statistics in http_reply

@load base/frameworks/sumstats

event zeek_init()
{
    print "Start to make 404 statistics";
    # Total number of http reply
    local r1 = SumStats::Reducer($stream="count of resp", $apply=set(SumStats::SUM));
    # Total number of http reply with 404
    local r2 = SumStats::Reducer($stream="count of 404", $apply=set(SumStats::SUM, SumStats::UNIQUE));

    SumStats::create([$name="detect attacker through 404 resp",
    # Time interval is 10 min
    $epoch=10min,
    $reducers=set(r1, r2),
    $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
    {
        # Total count of http reply
        local count_resp: double = result["count of resp"]$num;
        # Count of http reply with 404 status code
        local count_404: double = result["count of 404"]$num;
        # Count of http reply with 404 status code for unique uri
        local count_uni_404: double = result["count of 404"]$unique;

        # Ratio of 404
        local ratio_404: double = count_404 / count_resp;
        # Ratio of 404 for unique uri
        local ratio_uni_404:double = count_uni_404 / count_resp;
        
        if (count_404 > 2 && ratio_404 > 0.2 && ratio_uni_404 > 0.5)
        {
            print fmt("%s is a scanner with %s scan attemps on %s urls", key$host, result["count of 404"]$num, result["count of 404"]$unique);
        }
        
    }]);
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
    # All HTTP reply
    SumStats::observe("count of resp", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));

    # HTTP reply with 404 status code
    if (code == 404)
    {
        SumStats::observe("count of 404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
    }
}
