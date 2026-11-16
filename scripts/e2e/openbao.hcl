# OpenBao for scripts/e2e.sh. e2e.sh fills in @EDGEKMS_ADDR@, @SEAL_TOKEN@ and the two ports into
# a copy in its temp dir; this template holds no secrets. The container runs on the host network,
# so both listeners bind loopback only.
# OpenBao 2 has no file backend; single-node raft on the container's data volume is the
# smallest persistent one.
storage "raft" {
  path    = "/openbao/file"
  node_id = "e2e"
}

listener "tcp" {
  address         = "127.0.0.1:@BAO_PORT@"
  cluster_address = "127.0.0.1:@BAO_CLUSTER_PORT@"
  tls_disable     = true
}

seal "transit" {
  address    = "@EDGEKMS_ADDR@"
  token      = "@SEAL_TOKEN@"
  key_name   = "seal"
  mount_path = "transit/"
}

api_addr      = "http://127.0.0.1:@BAO_PORT@"
cluster_addr  = "http://127.0.0.1:@BAO_CLUSTER_PORT@"
disable_mlock = true
ui            = false
