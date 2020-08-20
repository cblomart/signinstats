# SigninStats

> **TODO**: render the user informations more flexible. Currently only the company name is collected.

Azure AD signing logs can be sent to log analytics :)

On some tenants these logs can take up quite a bit of storage. 

This projects aims at consolidating those logs at some time interval to lower the storage needed.

Admitedly these don't replace the original logs but they can give a sense of the amount and type of signins on a tenant.

## Principle

Ok... bear with me there...


```ascii
                                         +-----------+
                                         | Azure AD  |
                                         | User info |                    +--------------------+
                                         +-----+-----+                   -> Log Analytics      |
+---------+                                    |                        / | "simple" dashboard |
| sign-in |   +-------+   +-----------+   +----v-----+   +-----------+ /  +--------------------+
|   logs  +---> event +---> stream    +---> Azure    +---> Log       |/
| ------- |   |  hub  |   | analytics |   | function |   | Analytics |\
| ------- |   +-------+   +-----------+   +----^-----+   +-----------+ \ 
+---------/                                    |                        \ +-------------------+
                                           +---v---+                     -> Kibana            |
                                           | redis |                      | dynamic dashboard |
                                           | cache |                      +-------------------+
                                           +-------+
```

1. Azure AD signin logs are configured to be exported to an event hub
2. Stream Analytics picks up event from event hub and concatenate them per time slice (i.e. hours). Events are batched to an Azure function for enrichement.
3. An Azure function recieves the events batch and fetches user information from Azure AD (companyname) and caches it to redis
4. The aggregated and enriched information is sent to log analytics

## Setup

> **TODO**: complete setup instructions

### Log Analytics

### Azure Function

### Event Hub

### Stream Analytics

### Sign-in Logs