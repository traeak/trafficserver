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

ats="localhost:18080"

path="~p.tex/~s.2137859/etag/good"
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	| wc -c

path="~p.tex/~s.2137859/lm/good"
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	| wc -c

path="~p.tex/~s.2137859/etag/old2nd"
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	| wc -c

path="~p.tex/~s.2137859/lm/old2nd"
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	| wc -c

path="~p.tex/~s.2137859/etag/old1st"
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	| wc -c

path="~p.tex/~s.2137859/lm/old1st"
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	| wc -c

path="~p.tex/~s.2137859/etag/oldest2nd"
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	| wc -c

path="~p.tex/~s.2137859/lm/oldest2nd"
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	| wc -c

path="~p.tex/~s.2137859/etag/oldest1st"
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	| wc -c

path="~p.tex/~s.2137859/lm/oldest1st"
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	| wc -c

path="~p.tex/~s.2137859/etag/nocache2nd"
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	| wc -c

path="~p.tex/~s.2137859/lm/nocache2nd"
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	| wc -c

path="~p.tex/~s.2137859/etag/nocache1st"
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	| wc -c

path="~p.tex/~s.2137859/lm/nocache1st"
curl -Lv -x ${ats} \
	"http://slice/${path}" \
	| wc -c
