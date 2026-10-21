//// Every usage example runs here against the local test provider.

import warden_reference/usage/callback_addresses
import warden_reference/usage/durable_store
import warden_reference/usage/resource_server
import warden_reference/usage/responsibilities
import warden_reference/usage/supervision
import warden_reference/usage/test_provider

pub fn supervision_test() {
  supervision.run()
}

pub fn durable_store_test() {
  durable_store.run()
}

pub fn conditional_writes_test() {
  durable_store.conditional_writes()
}

pub fn resource_server_test() {
  resource_server.run()
}

pub fn callback_addresses_test() {
  callback_addresses.run()
}

pub fn test_provider_test() {
  test_provider.run()
}

pub fn responsibilities_test() {
  responsibilities.run()
}
