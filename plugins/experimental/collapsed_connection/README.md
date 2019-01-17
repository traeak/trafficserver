collapsed connection Plugin
===========================

This remap plugin is yet another attempt at upstream thundering herd
mitigation which works by forcing a thundering herd to wait for
parent data to be cached OR parent response headers to be cached in
the event of a cache failure.

The simplest description of this plugin is that it only allows one leader
transaction per cache key per time slice to resolve the cache state
for all transactions in that group.  All other transactions within that
slice end up either serve cache data as fetched/verified by the leader
or send a copy of the leader's headers back to their respective clients.

Time slices can be configured from 500ms to 5000ms long.  Group
members will wait until the leader has an answer or their clients go
away. Any leader fetches from origin are placed in an independent
continuation to ensure the cache data is fetched regardless of
the leader's client status.  **NOTE** this needs to be removed as
proxy.config.http.background_fill_active_timeout and friends already
do this.


For now these tasks to complete the collapsed_connection plugin in its
current state:

	- A group leader's headers (and not just response code) should be cached
	for a cache fail.
	- Ensure group member retry_handler loop deals with client abort/timeouts.

Also there are likely bugs in this plugin as I observed one group
returning a rash of 500's (didn't repeat) at one time during synthetic
load testing.
