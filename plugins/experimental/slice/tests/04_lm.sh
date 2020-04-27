#!/bin/bash

#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

#curl -Lv -x http://localhost:8080 \
#	"http://~p.tex/~s.2300000/a" \
#	-H "X-Dtp: ~f.posevt,~posevt.1000005.etag0.foo.etag1.bar" \
#	-r 999999-1004910 \
#	| wc -c

timenow=`date +%s`
timetoday=$(((timenow / 86400) * 86400))

ats="localhost:18080"
time1st=$((timetoday - 200))
time2nd=$((timetoday - 100))
time3rd=$((timetoday - 50))
cchdr="max-age=50000"
path="~p.tex/~s.2137859/04_lm/oldest1st"

# Last-Modified tests
echo "all out of date, 1st slice even more out of date"

# 1st slice old (everything out of date)
curl -x ${ats} \
	"http://cache_range_requests/${path}" \
	-H "X-Dtp: ~lm.${time1st}" \
	-H "X-Dtp-Cc: ${cchdr}" \
	-r 0-999999 \
	| wc -c

sleep 1

curl -x ${ats} \
	"http://cache_range_requests/${path}" \
	-H "X-Dtp: ~lm.${time2nd}" \
	-H "X-Dtp-Cc: ${cchdr}" \
	-r 1000000-1999999 \
	| wc -c

curl -x ${ats} \
	"http://cache_range_requests/${path}" \
	-H "X-Dtp: ~lm.${time2nd}" \
	-H "X-Dtp-Cc: ${cchdr}" \
	-r 2000000-2999999 \
	| wc -c

# 1st slice old (everything out of date)
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	-H "X-Dtp: ~lm.${time3rd}" \
	-H "X-Dtp-Cc: ${cchdr}" \
	-r 1000000- \
	| wc -c

# 1st slice old (everything out of date)
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	-H "X-Dtp: ~lm.${time3rd}" \
	-H "X-Dtp-Cc: ${cchdr}" \
	| wc -c

