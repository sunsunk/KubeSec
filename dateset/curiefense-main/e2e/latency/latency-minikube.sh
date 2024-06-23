#!/bin/sh

OUTFILE="data-$(date +'%Y%m%d%H%M%S').csv"
URL="http://192.168.49.2:30081/productpage" 
echo "duration,connections,target_qps,actual_qps,p90latency,p99latency" > "$OUTFILE"

DURATION=60s

for CONNECTIONS in 10 250 500; do
	for QPS in 35 70 150 300 600 1200 2400 4800; do
		FORTIODATA=$(fortio load -qps "$QPS" -t "$DURATION" -c "$CONNECTIONS" -json - "$URL" \
			|jq '. | [.ActualQPS, (.DurationHistogram.Percentiles[] | select(.Percentile==90)
| .Value), (.DurationHistogram.Percentiles[] | select(.Percentile==99) | .Value) ] | @csv' \
			| tr -d '"')
		echo "$DURATION,$CONNECTIONS,$QPS,$FORTIODATA" >> "$OUTFILE"
	done
done
