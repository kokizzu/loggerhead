# Loggerhead

Loggerhead is geolocation database built in go. It is designed to be fast and efficient, and to be used in a distributed
like kubernetes.

It makes use of hashicorp/memberlist to provide a gossip based membership system, and uses a custom protocol to
synchronize the database between nodes.

## Usage

The database expose multiple ports for different purposes:

- 19998: for read queries.
- 19999: for write queries.
- 20000: for metrics(prometheus) and admin interface where you can visualize the state of the cluster
- 20001: for the gossip protocol to communicate with other nodes

## Configuration

The database can be configured using environment variables or command line arguments.
So far only one configuration is supported:

- CLUSTER_DNS: the dns name of the cluster, this is used to discover other nodes in the cluster by extracting the
  ip addresses from the dns name (very convenient for kubernetes).
- SEED_NODES (coming soon): a list of seed nodes to bootstrap the cluster.

## Building

The database require go 1.22.1 and GCC to build.

```shell
CGO_ENABLED=1 GOARCH=$TARGETARCH go build -o loggerhead
```

## Running

```shell

./loggerhead --cluster-dns=loggerhead.default.svc.cluster.local

```

The output will look like so:

```
2024/06/10 01:44:07 Please set the following environment variables:
2024/06/10 01:44:07 CLUSTER_DNS
2024/06/10 01:44:07 Reverting to flags...
2024/06/10 01:44:07 [DEBUG] memberlist: Initiating push/pull sync with:  [::1]:20001
2024/06/10 01:44:07 [DEBUG] memberlist: Stream connection from=[::1]:42194
2024/06/10 01:44:07 Sharing local state to a new node
2024/06/10 01:44:07 Sharing local state to a new node
2024/06/10 01:44:07 [DEBUG] memberlist: Initiating push/pull sync with:  172.45.0.2:20001
2024/06/10 01:44:07 Sharing local state to a new node
2024/06/10 01:44:07 [DEBUG] memberlist: Stream connection from=172.45.0.2:48278
2024/06/10 01:44:07 Sharing local state to a new node
2024/06/10 01:44:07 [DEBUG] memberlist: Initiating push/pull sync with:  172.45.0.2:20001
2024/06/10 01:44:07 Sharing local state to a new node
2024/06/10 01:44:07 [DEBUG] memberlist: Stream connection from=172.45.0.2:48282
2024/06/10 01:44:07 Sharing local state to a new node
===========================================================
Starting the Database Server
Cluster DNS:  loggerhead.default.svc.cluster.local
Use the following ports for the following services:
Writing location update: 19999
Reading location update: 19998
Admin UI (/) & Metrics(/metrics): 20000
Clustering: 20001
===========================================================

```