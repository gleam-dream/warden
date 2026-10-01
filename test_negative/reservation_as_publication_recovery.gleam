// expect: Type mismatch
import warden

pub fn main(
  client: warden.Client,
  recovery: warden.RefreshReservationRecovery,
) {
  warden.recover_refresh_publication(client, recovery)
}
