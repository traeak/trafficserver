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
etag1st="first"
etag2nd="second"
etag3rd="third"
cchdr="max-age=1000000"
path="~p.tex/~s.2137859/etag/oldest1st"

# Last-Modified tests .. order of injection matters here
echo "all out of date, 1st slice even more out of date"

# 1st slice oldest
curl -x ${ats} \
	"http://cache_range_requests/${path}" \
	-H "X-Dtp: ~etag.${etag1st}" \
	-H "X-Dtp-Cc: ${cchdr}" \
	-r 0-999999 \
	| wc -c

sleep 1

curl -x ${ats} \
	"http://cache_range_requests/${path}" \
	-H "X-Dtp: ~etag.${etag2nd}" \
	-H "X-Dtp-Cc: ${cchdr}" \
	-r 1000000-1999999 \
	| wc -c

curl -x ${ats} \
	"http://cache_range_requests/${path}" \
	-H "X-Dtp: ~etag.${etag2nd}" \
	-H "X-Dtp-Cc: ${cchdr}" \
	-r 2000000-2999999 \
	| wc -c

# 1st slice old (everything out of date)
curl -Lv -x ${ats} \
 	"http://slice/${path}" \
	-H "X-Dtp: ~etag.${etag3rd}" \
	-H "X-Dtp-Cc: ${cchdr}" \
	-r 1000000- \
	| wc -c

# 1st slice old (everything out of date)
curl -Lv -x ${ats} \
 	"http://slice/${path}" \
	-H "X-Dtp: ~etag.${etag3rd}" \
	-H "X-Dtp-Cc: ${cchdr}" \
	| wc -c

