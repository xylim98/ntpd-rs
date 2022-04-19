// An implementation of the NTP clock filter algorithm, as described by
//
//      https://datatracker.ietf.org/doc/html/rfc5905#page-37
//
// Specifically this is a rust implementation of the `clock_filter()` routine,
// described in the appendix
//
//      https://datatracker.ietf.org/doc/html/rfc5905#appendix-A.5.2

use std::net::IpAddr;

use crate::{packet::NtpLeapIndicator, NtpDuration, NtpHeader, NtpTimestamp, ReferenceId};

const MAX_STRATUM: u8 = 16;
const MAX_DISTANCE: NtpDuration = NtpDuration::ONE;

const BURST_INTERVAL: NtpDuration = NtpDuration::ONE.multiply_by(2);

/// frequency tolerance (15 ppm)
// const PHI: f64 = 15e-6;
fn multiply_by_phi(duration: NtpDuration) -> NtpDuration {
    (duration * 15) / 1_000_000
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct FilterTuple {
    offset: NtpDuration,
    delay: NtpDuration,
    dispersion: NtpDuration,
    time: NtpTimestamp,
}

impl FilterTuple {
    const DUMMY: Self = Self {
        offset: NtpDuration::ZERO,
        delay: NtpDuration::MAX_DISPERSION,
        dispersion: NtpDuration::MAX_DISPERSION,
        time: NtpTimestamp::ZERO,
    };

    fn is_dummy(self) -> bool {
        self == Self::DUMMY
    }

    fn from_packet(
        packet: &NtpHeader,
        system_precision: NtpDuration,
        destination_timestamp: NtpTimestamp,
        local_clock_time: NtpTimestamp,
    ) -> Self {
        // for reference
        //
        // | org       | T1         | origin timestamp      |
        // | rec       | T2         | receive timestamp     |
        // | xmt       | T3         | transmit timestamp    |
        // | dst       | T4         | destination timestamp |

        let packet_precision = NtpDuration::from_exponent(packet.precision);

        if let crate::packet::NtpAssociationMode::Broadcast = packet.mode {
            // const BROADCAST_DELAY: NtpDuration = NtpDuration::ONE.divided_by(250); // 0.004
            //
            // let offset = packet.transmit_timestamp - destination_timestamp;
            // let delay = BROADCAST_DELAY;
            // let dispersion =
            //     packet_precision + system_precision + multiply_by_phi(BROADCAST_DELAY * 2i64);
            //
            // FilterTuple {
            //     offset,
            //     delay,
            //     dispersion,
            //     time: local_clock_time,
            // }
            todo!("implement updating the peer with a broadcast packet")
        } else {
            // offset is the average of the deltas (T2 - T1) and (T4 - T3)
            let offset1 = packet.receive_timestamp - packet.origin_timestamp;
            let offset2 = destination_timestamp - packet.transmit_timestamp;
            let offset = (offset1 + offset2) / 2i64;

            // delay is (T4 - T1) - (T3 - T2)
            let delta1 = destination_timestamp - packet.origin_timestamp;
            let delta2 = packet.transmit_timestamp - packet.receive_timestamp;
            // In cases where the server and client clocks are running at different rates
            // and with very fast networks, the delay can appear negative.
            // delay is clamped to ensure it is always positive
            let delay = system_precision.max(delta1 - delta2);

            let dispersion = packet_precision + system_precision + multiply_by_phi(delta1);

            FilterTuple {
                offset,
                delay,
                dispersion,
                time: local_clock_time,
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct LastMeasurements {
    register: [FilterTuple; 8],
}

impl Default for LastMeasurements {
    fn default() -> Self {
        Self::new()
    }
}

impl LastMeasurements {
    #[allow(dead_code)]
    const fn new() -> Self {
        Self {
            register: [FilterTuple::DUMMY; 8],
        }
    }

    /// Insert the new tuple at index 0, move all other tuples one to the right.
    /// The final (oldest) tuple is discarded
    fn shift_and_insert(&mut self, mut current: FilterTuple, dispersion_correction: NtpDuration) {
        for tuple in self.register.iter_mut() {
            // adding the dispersion correction would make the dummy no longer a dummy
            if !tuple.is_dummy() {
                tuple.dispersion += dispersion_correction;
            }

            std::mem::swap(&mut current, tuple);
        }
    }
}

/// Temporary list
#[derive(Debug, Clone)]
struct TemporaryList {
    /// Invariant: this array is always sorted by increasing delay!
    register: [FilterTuple; 8],
}

impl TemporaryList {
    fn from_clock_filter_contents(source: &LastMeasurements) -> Self {
        // copy the registers
        let mut register = source.register;

        // sort by delay, ignoring NaN
        register.sort_by(|t1, t2| {
            t1.delay
                .partial_cmp(&t2.delay)
                .unwrap_or(std::cmp::Ordering::Less)
        });

        Self { register }
    }

    fn smallest_delay(&self) -> &FilterTuple {
        &self.register[0]
    }

    /// Prefix of the temporary list containing only the valid tuples
    fn valid_tuples(&self) -> &[FilterTuple] {
        let num_invalid_tuples = self
            .register
            .iter()
            .rev()
            .take_while(|t| t.is_dummy())
            .count();

        let num_valid_tuples = self.register.len() - num_invalid_tuples;

        &self.register[..num_valid_tuples]
    }

    /// #[no_run]
    ///                     i=n-1
    ///                     ---     epsilon_i
    ///      epsilon =       \     ----------
    ///                      /        (i+1)
    ///                     ---     2
    ///                     i=0
    /// Invariant: the register is sorted wrt delay
    fn dispersion(&self) -> NtpDuration {
        self.register
            .iter()
            .enumerate()
            .map(|(i, t)| t.dispersion / 2i64.pow(i as u32 + 1))
            .fold(NtpDuration::default(), |a, b| a + b)
    }

    /// #[no_run]
    ///                          +-----                 -----+^1/2
    ///                          |  n-1                      |
    ///                          |  ---                      |
    ///                  1       |  \                     2  |
    ///      psi   =  -------- * |  /    (theta_0-theta_j)   |
    ///                (n-1)     |  ---                      |
    ///                          |  j=1                      |
    ///                          +-----                 -----+
    ///
    /// Invariant: the register is sorted wrt delay
    fn jitter(&self, smallest_delay: FilterTuple, system_precision: f64) -> f64 {
        Self::jitter_help(self.valid_tuples(), smallest_delay, system_precision)
    }

    fn jitter_help(
        valid_tuples: &[FilterTuple],
        smallest_delay: FilterTuple,
        system_precision: f64,
    ) -> f64 {
        let root_mean_square = valid_tuples
            .iter()
            .map(|t| (t.offset - smallest_delay.offset).to_seconds().powi(2))
            .sum::<f64>()
            .sqrt();

        // root mean square average (RMS average). - 1 to exclude the smallest_delay
        let jitter = root_mean_square / (valid_tuples.len() - 1) as f64;

        // In order to ensure consistency and avoid divide exceptions in other
        // computations, the psi is bounded from below by the system precision
        // s.rho expressed in seconds.
        jitter.max(system_precision)
    }

    #[cfg(test)]
    const fn new() -> Self {
        Self {
            register: [FilterTuple::DUMMY; 8],
        }
    }
}

#[derive(Debug, Default)]
pub struct PeerStatistics {
    pub offset: NtpDuration,
    pub delay: NtpDuration,

    pub dispersion: NtpDuration,
    pub jitter: f64,
}

#[allow(dead_code)]
#[derive(Debug)]
struct PeerConfiguration {
    source_address: IpAddr,
    source_port: u16,
    destination_address: IpAddr,
    destination_port: u16,
    reference_id: ReferenceId,
}

pub struct Peer {
    statistics: PeerStatistics,
    last_measurements: LastMeasurements,
    last_packet: NtpHeader,
    time: NtpTimestamp,
    #[allow(dead_code)]
    peer_id: ReferenceId,
    our_id: ReferenceId,

    host_poll: NtpDuration,

    /// In burst mode, many packets are sent in rapid succession to quickly synchronize
    /// This value is the burst count, the number of packages that still need to be sent
    /// until the burst is over. If 0, we are not in burst mode.
    burst: u8,

    out_date: NtpTimestamp,
    next_date: NtpTimestamp,

    reach: Reach,
}

/// Used to determine whether the server is reachable and the data are fresh
/// The register is shifted left by one bit when a packet is sent and the
/// rightmost bit is set to zero.  As valid packets arrive, the rightmost bit is set to one.
/// If the register contains any nonzero bits, the server is considered reachable;
/// otherwise, it is unreachable.
#[derive(Debug, Default)]
struct Reach(u8);

impl Reach {
    #[allow(dead_code)]
    fn is_reachable(&self) -> bool {
        self.0 != 0
    }

    /// We have just received a packet, so the peer is definitely reachable
    fn received_packet(&mut self) {
        self.0 |= 1;
    }

    /// A packet received some number of poll intervals ago is decreasingly relevant for
    /// determining that a peer is still reachable. We discount the packets received so far.
    #[allow(dead_code)]
    fn poll(&mut self) {
        self.0 <<= 1
    }
}

pub enum Decision {
    Ignore,
    Process,
}

impl Peer {
    #[allow(dead_code)]
    pub fn clock_filter(
        &mut self,
        new_tuple: FilterTuple,
        system_leap_indicator: NtpLeapIndicator,
        system_precision: f64,
    ) -> Decision {
        let dispersion_correction = multiply_by_phi(new_tuple.time - self.time);
        self.last_measurements
            .shift_and_insert(new_tuple, dispersion_correction);

        let temporary_list = TemporaryList::from_clock_filter_contents(&self.last_measurements);
        let smallest_delay = *temporary_list.smallest_delay();

        // Prime directive: use a sample only once and never a sample
        // older than the latest one, but anything goes before first
        // synchronized.
        if smallest_delay.time - self.time <= NtpDuration::ZERO
            && system_leap_indicator.is_synchronized()
        {
            return Decision::Ignore;
        }

        let offset = smallest_delay.offset;
        let delay = smallest_delay.delay;

        let dispersion = temporary_list.dispersion();
        let jitter = temporary_list.jitter(smallest_delay, system_precision);

        let statistics = PeerStatistics {
            offset,
            delay,
            dispersion,
            jitter,
        };

        self.statistics = statistics;
        self.time = smallest_delay.time;

        Decision::Process
    }

    /// The root synchronization distance is the maximum error due to
    /// all causes of the local clock relative to the primary server.
    /// It is defined as half the total delay plus total dispersion
    /// plus peer jitter.
    #[allow(dead_code)]
    fn root_distance(&self, local_clock_time: NtpTimestamp) -> NtpDuration {
        NtpDuration::MIN_DISPERSION.max(self.last_packet.root_delay + self.statistics.delay) / 2i64
            + self.last_packet.root_dispersion
            + self.statistics.dispersion
            + multiply_by_phi(local_clock_time - self.time)
            + NtpDuration::from_seconds(self.statistics.jitter)
    }

    #[allow(dead_code)]
    /// Test if association p is acceptable for synchronization
    ///
    /// Known as `accept` and `fit` in the specification.
    fn accept_synchronization(
        &self,
        local_clock_time: NtpTimestamp,
        system_poll: NtpDuration,
    ) -> bool {
        // A stratum error occurs if
        //     1: the server has never been synchronized,
        //     2: the server stratum is invalid
        if !self.last_packet.leap.is_synchronized() || self.last_packet.stratum >= MAX_STRATUM {
            return false;
        }

        //  A distance error occurs if the root distance exceeds the
        //  distance threshold plus an increment equal to one poll interval.
        let distance = self.root_distance(local_clock_time);

        if distance > MAX_DISTANCE + multiply_by_phi(system_poll) {
            return false;
        }

        // Detect whether the remote uses us as their main time reference.
        // if so, we shouldn't sync to them as that would create a loop.
        // Note, this can only ever be an issue if the peer is not using
        // hardware as its source, so ignore reference_id if stratum is 1.
        if self.last_packet.stratum != 1 && self.last_packet.reference_id == self.our_id {
            return false;
        }

        // TODO: An unreachable error occurs if the server is unreachable.

        true
    }

    #[allow(dead_code)]
    fn update_with_packet(
        &mut self,
        local_clock_time: NtpTimestamp,
        system_precision: NtpDuration,
        mut packet: NtpHeader,
        destination_timestamp: NtpTimestamp,
    ) -> Option<FilterTuple> {
        // we map stratum 0 (unspecified) to MAXSTRAT to make stratum
        // comparisons simpler and to provide a natural interface
        // for radio clock drivers that operate for convenience at stratum 0.
        if packet.stratum == 0 {
            packet.stratum = MAX_STRATUM;
        }

        self.last_packet = packet;

        // Verify the server is synchronized with valid stratum and
        // reference time not later than the transmit time.
        if !self.last_packet.leap.is_synchronized() || self.last_packet.stratum >= MAX_STRATUM {
            // this peer is unsynchronized
            return None;
        }

        // verify root distance
        let packet_dispersion =
            self.last_packet.root_delay / 2i64 + self.last_packet.root_dispersion;
        let time_travel =
            self.last_packet.reference_timestamp > self.last_packet.transmit_timestamp;
        if packet_dispersion >= NtpDuration::MAX_DISPERSION || time_travel {
            return None; /* invalid header values */
        }

        // host_poll
        let poll_interval = self.host_poll;
        self.poll_update(local_clock_time, poll_interval);
        self.reach.received_packet();

        let tuple = FilterTuple::from_packet(
            &packet,
            system_precision,
            destination_timestamp,
            local_clock_time,
        );

        Some(tuple)
    }

    /// update the poll interval for this Peer
    #[allow(dead_code)]
    fn poll_update(&mut self, local_clock_time: NtpTimestamp, poll_interval: NtpDuration) {
        const MIN_POLL: i8 = 4; // 16 seconds
        const MAX_POLL: i8 = 17; // 36 hours

        self.host_poll = clamp_ntp_duration(
            NtpDuration::from_exponent(MIN_POLL),
            poll_interval,
            NtpDuration::from_exponent(MAX_POLL),
        );

        if self.burst > 0 {
            // deviation: code skeleton uses `self.next_date != local_clock_time`
            // that seems dangerous. I think we only want to schedule the next
            // time to send a packet when the current deadline has passed
            if self.next_date < local_clock_time {
                return;
            } else {
                self.next_date += BURST_INTERVAL;
            }
        } else {
            // TODO: randomize the poll interval by a small factor
            let offset = clamp_ntp_duration(
                NtpDuration::from_exponent(MIN_POLL),
                self.host_poll,
                NtpDuration::from_exponent(self.last_packet.poll),
            );
            self.next_date = self.out_date + offset;
        }

        if self.next_date < local_clock_time {
            self.next_date = local_clock_time + NtpDuration::ONE;
        }
    }
}

fn clamp_ntp_duration(
    lower_bound: NtpDuration,
    value: NtpDuration,
    upper_bound: NtpDuration,
) -> NtpDuration {
    value.min(upper_bound).max(lower_bound)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i8)]
enum EndpointType {
    Upper = 1,
    Middle = 0,
    Lower = -1,
}

#[allow(dead_code)]
struct CandidateTuple<'a> {
    peer: &'a Peer,
    endpoint_type: EndpointType,
    /// Correctness interval edge
    edge: NtpDuration,
}

#[allow(dead_code)]
fn construct_candidate_list<'a>(
    valid_associations: impl Iterator<Item = &'a Peer>,
    local_clock_time: NtpTimestamp,
) -> Vec<CandidateTuple<'a>> {
    let mut candidate_list = Vec::new();

    for peer in valid_associations {
        let offset = peer.statistics.offset;

        let tuples = [
            CandidateTuple {
                peer,
                endpoint_type: EndpointType::Upper,
                edge: offset + peer.root_distance(local_clock_time),
            },
            CandidateTuple {
                peer,
                endpoint_type: EndpointType::Middle,
                edge: offset,
            },
            CandidateTuple {
                peer,
                endpoint_type: EndpointType::Lower,
                edge: offset - peer.root_distance(local_clock_time),
            },
        ];

        candidate_list.extend(tuples)
    }

    candidate_list.sort_by(|a, b| a.edge.cmp(&b.edge));

    candidate_list
}

#[allow(dead_code)]
struct SurvivorTuple<'a> {
    p: &'a Peer,
    metric: NtpDuration,
}

/// Collect the candidates within the correctness interval
#[allow(dead_code)]
fn construct_survivors<'a>(
    chime_list: &'a [CandidateTuple<'a>],
    local_clock_time: NtpTimestamp,
) -> Vec<SurvivorTuple<'a>> {
    match find_interval(chime_list) {
        Some((low, high)) => chime_list
            .iter()
            .filter_map(|candidate| filter_survivor(candidate, local_clock_time, low, high))
            .collect(),
        None => vec![],
    }
}

fn filter_survivor<'a>(
    candidate: &'a CandidateTuple<'a>,
    local_clock_time: NtpTimestamp,
    low: NtpDuration,
    high: NtpDuration,
) -> Option<SurvivorTuple<'a>> {
    // To be a truechimer, a peers middle (actual offset)
    // needs to lie within the consistency interval.
    // Note: The standard is unclear on this, but this
    // is what gives sensible results in combination with
    // how interval selection works.
    if candidate.edge < low
        || candidate.edge > high
        || candidate.endpoint_type != EndpointType::Middle
    {
        None
    } else {
        let p = candidate.peer;
        let metric = MAX_DISTANCE * p.last_packet.stratum + p.root_distance(local_clock_time);

        Some(SurvivorTuple { p, metric })
    }
}

/// Find the largest contiguous intersection of correctness intervals.
#[allow(dead_code)]
fn find_interval(chime_list: &[CandidateTuple]) -> Option<(NtpDuration, NtpDuration)> {
    let n = chime_list.len() / 3;

    let mut low = None;
    let mut high = None;

    // allow is the number of allowed falsetickers
    for allow in (0..).take_while(|allow| 2 * allow < n) {
        let mut found = 0; // variable "d", falsetickers found in the current iteration
        let mut chime = 0; // variable "c"

        // Scan the chime list from lowest to highest to find the lower endpoint.
        // any middle that we find before the lower endpoint counts as a falseticker
        for tuple in chime_list {
            chime -= tuple.endpoint_type as i32;

            // the code skeleton uses `n - found` here, which is wrong!
            if chime >= (n - allow) as i32 {
                low = Some(tuple.edge);
                break;
            }

            if let EndpointType::Middle = tuple.endpoint_type {
                found += 1;
            }
        }

        // Scan the chime list from highest to lowest to find the upper endpoint.
        // any middle that we find before the upper endpoint counts as a falseticker
        chime = 0;
        for tuple in chime_list.iter().rev() {
            chime += tuple.endpoint_type as i32;

            // the code skeleton uses `n - found` here, which is wrong!
            if chime >= (n - allow) as i32 {
                high = Some(tuple.edge);
                break;
            }

            if let EndpointType::Middle = tuple.endpoint_type {
                found += 1;
            }
        }

        // counted more falsetickers than allowed in this iteration;
        // we loop and try again allowing one more falseticker
        if found > allow {
            continue;
        }

        //  If the intersection is non-empty, declare success.
        if let (Some(l), Some(h)) = (low, high) {
            return Some((l, h));
        }
    }

    None
}

#[cfg(test)]
mod test {
    use crate::packet::NtpAssociationMode;

    use super::*;

    fn default_peer() -> Peer {
        Peer {
            statistics: Default::default(),
            last_measurements: Default::default(),
            last_packet: Default::default(),
            time: Default::default(),
            host_poll: Default::default(),
            burst: Default::default(),
            out_date: Default::default(),
            next_date: Default::default(),
            reach: Default::default(),
            peer_id: ReferenceId::from_int(0),
            our_id: ReferenceId::from_int(0),
        }
    }

    #[test]
    fn dispersion_of_dummys() {
        // The observer should note (a) if all stages contain the dummy tuple
        // with dispersion MAXDISP, the computed dispersion is a little less than 16 s

        let register = TemporaryList::new();
        let value = register.dispersion().to_seconds();

        assert!((16.0 - value) < 0.1)
    }

    #[test]
    fn dummys_are_not_valid() {
        assert!(TemporaryList::new().valid_tuples().is_empty())
    }

    #[test]
    fn jitter_of_single() {
        let mut register = LastMeasurements::new();
        register.register[0].offset = NtpDuration::from_seconds(42.0);
        let first = register.register[0];
        let value = TemporaryList::from_clock_filter_contents(&register).jitter(first, 0.0);

        assert_eq!(value, 0.0)
    }

    #[test]
    fn jitter_of_pair() {
        let mut register = TemporaryList::new();
        register.register[0].offset = NtpDuration::from_seconds(20.0);
        register.register[1].offset = NtpDuration::from_seconds(30.0);
        let first = register.register[0];
        let value = register.jitter(first, 0.0);

        // jitter is calculated relative to the first tuple
        assert!((value - 10.0).abs() < 1e-6)
    }

    #[test]
    fn jitter_of_triple() {
        let mut register = TemporaryList::new();
        register.register[0].offset = NtpDuration::from_seconds(20.0);
        register.register[1].offset = NtpDuration::from_seconds(20.0);
        register.register[2].offset = NtpDuration::from_seconds(30.0);
        let first = register.register[0];
        let value = register.jitter(first, 0.0);

        // jitter is calculated relative to the first tuple
        assert!((value - 5.0).abs() < 1e-6)
    }

    #[test]
    fn clock_filter_defaults() {
        let leap_indicator = NtpLeapIndicator::NoWarning;
        let system_precision = 0.0;

        let new_tuple = FilterTuple {
            offset: Default::default(),
            delay: Default::default(),
            dispersion: Default::default(),
            time: Default::default(),
        };

        let mut peer = default_peer();

        let update = peer.clock_filter(new_tuple, leap_indicator, system_precision);

        // because "time" is zero, the same as all the dummy tuples,
        // the "new" tuple is not newer and hence rejected
        assert!(matches!(update, Decision::Ignore));
    }

    #[test]
    fn clock_filter_new() {
        let leap_indicator = NtpLeapIndicator::NoWarning;
        let system_precision = 0.0;

        let new_tuple = FilterTuple {
            offset: NtpDuration::from_seconds(12.0),
            delay: NtpDuration::from_seconds(14.0),
            dispersion: Default::default(),
            time: NtpTimestamp::from_bits((1i64 << 32).to_be_bytes()),
        };

        let mut peer = default_peer();

        let update = peer.clock_filter(new_tuple, leap_indicator, system_precision);

        assert!(matches!(update, Decision::Process));

        assert_eq!(peer.statistics.offset, new_tuple.offset);
        assert_eq!(peer.statistics.delay, new_tuple.delay);
        assert_eq!(peer.time, new_tuple.time);

        // there is just one valid sample
        assert_eq!(peer.statistics.jitter, 0.0);

        let temporary = TemporaryList::from_clock_filter_contents(&peer.last_measurements);

        assert_eq!(temporary.register[0], new_tuple);
        assert_eq!(temporary.valid_tuples(), &[new_tuple]);
    }

    #[test]
    fn update_with_unsynchronized_packet() {
        let mut peer = default_peer();
        let mut packet = NtpHeader::default();

        packet.leap = NtpLeapIndicator::Unknown;

        let local_clock_time = NtpTimestamp::ZERO;
        let system_precision = NtpDuration::ZERO;
        let destination_timestamp = NtpTimestamp::ZERO;

        let update = peer.update_with_packet(
            local_clock_time,
            system_precision,
            packet,
            destination_timestamp,
        );

        assert!(update.is_none());
    }

    #[test]
    fn update_with_invalid_stratum() {
        let mut peer = default_peer();
        let mut packet = NtpHeader::default();

        packet.stratum = 42;

        let local_clock_time = NtpTimestamp::ZERO;
        let system_precision = NtpDuration::ZERO;
        let destination_timestamp = NtpTimestamp::ZERO;

        let update = peer.update_with_packet(
            local_clock_time,
            system_precision,
            packet,
            destination_timestamp,
        );

        assert!(update.is_none());
    }

    #[test]
    fn filter_tuple_from_packet_standard() {
        let mut packet = NtpHeader::default();

        packet.mode = NtpAssociationMode::Client;

        let local_clock_time = NtpTimestamp::ZERO;
        let system_precision = NtpDuration::ZERO;

        let seconds = |t| NtpTimestamp::from_seconds_nanos_since_ntp_era(t, 0);

        packet.origin_timestamp = seconds(0); // T1
        packet.receive_timestamp = seconds(10); // T2
        packet.transmit_timestamp = seconds(20); // T3
        let destination_timestamp = seconds(30); // T4

        let tuple = FilterTuple::from_packet(
            &packet,
            system_precision,
            destination_timestamp,
            local_clock_time,
        );

        let expected = FilterTuple {
            // offset is the average of the deltas (T2 - T1) and (T4 - T3)
            offset: NtpDuration::from_seconds(10.0),

            // delay is (T4 - T1) - (T3 - T2)
            delay: NtpDuration::from_seconds(20.0),

            // packet.precision is zero, but it's an exponent and 2^0 is 1
            dispersion: NtpDuration::ONE + multiply_by_phi(NtpDuration::from_seconds(30.0)),

            time: NtpTimestamp::ZERO,
        };

        assert_eq!(tuple, expected);
    }

    #[test]
    fn filter_tuple_from_packet_negative_delay() {
        // In cases where the server and client clocks are running at different rates
        // and with very fast networks, the delay can appear negative.
        // delay is clamped to ensure it is always positive

        let mut packet = NtpHeader::default();

        packet.mode = NtpAssociationMode::Client;

        let local_clock_time = NtpTimestamp::ZERO;
        let system_precision = NtpDuration::ONE;

        let seconds = |t| NtpTimestamp::from_seconds_nanos_since_ntp_era(t, 0);

        // NOTE: T3 > T4: packet is transmitted by the server after it is received by the client
        packet.origin_timestamp = seconds(0); // T1
        packet.receive_timestamp = seconds(10); // T2
        packet.transmit_timestamp = seconds(40); // T3
        let destination_timestamp = seconds(30); // T4

        let tuple = FilterTuple::from_packet(
            &packet,
            system_precision,
            destination_timestamp,
            local_clock_time,
        );

        assert_eq!(tuple.delay, system_precision);
    }

    #[test]
    fn reachability() {
        let mut reach = Reach::default();

        // the default reach register value is 0, and hence not reachable
        assert!(!reach.is_reachable());

        // when we receive a packet, we set the right-most bit;
        // we just received a packet from the peer, so it is reachable
        reach.received_packet();
        assert!(reach.is_reachable());

        // on every poll, the register is shifted to the left, and there are
        // 8 bits. So we can poll 7 times and the peer is still considered reachable
        for _ in 0..7 {
            reach.poll();
        }

        assert!(reach.is_reachable());

        // but one more poll and all 1 bits have been shifted out;
        // the peer is no longer reachable
        reach.poll();
        assert!(!reach.is_reachable());

        // until we receive a packet from it again
        reach.received_packet();
        assert!(reach.is_reachable());
    }

    #[test]
    fn find_interval_simple() {
        let peer_1 = default_peer();
        let peer_2 = default_peer();
        let peer_3 = default_peer();

        let intervals = [
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-4),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-3),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-2),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-1),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(0),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(1),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(2),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(3),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(4),
            },
        ];

        assert_eq!(
            find_interval(&intervals),
            Some((
                NtpDuration::from_fixed_int(-2),
                NtpDuration::from_fixed_int(2)
            ))
        );

        let survivors = construct_survivors(&intervals, NtpTimestamp::from_fixed_int(0));
        assert_eq!(survivors.len(), 3);
    }

    #[test]
    fn find_interval_outlier() {
        let peer_1 = default_peer();
        let peer_2 = default_peer();
        let peer_3 = default_peer();

        let intervals = [
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-4),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-3),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-1),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(0),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(2),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(3),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(15),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(16),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(17),
            },
        ];

        assert_eq!(
            find_interval(&intervals),
            Some((
                NtpDuration::from_fixed_int(-3),
                NtpDuration::from_fixed_int(2)
            ))
        );

        let survivors = construct_survivors(&intervals, NtpTimestamp::from_fixed_int(0));
        assert_eq!(survivors.len(), 2);
    }

    #[test]
    fn find_interval_low_precision_edgecase() {
        // One larger interval whose middle does not lie in
        // both smaller intervals, but whose middles do overlap.
        let peer_1 = default_peer();
        let peer_2 = default_peer();
        let peer_3 = default_peer();

        let intervals = [
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-10),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-3),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-2),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-1),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(0),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(2),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(3),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(5),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(6),
            },
        ];

        assert_eq!(
            find_interval(&intervals),
            Some((
                NtpDuration::from_fixed_int(-3),
                NtpDuration::from_fixed_int(5)
            ))
        );

        let survivors = construct_survivors(&intervals, NtpTimestamp::from_fixed_int(0));
        assert_eq!(survivors.len(), 3);
    }

    #[test]
    fn find_interval_interleaving_edgecase() {
        // Three partially overlapping intervals, where
        // the outer center's are not in each others interval.
        let peer_1 = default_peer();
        let peer_2 = default_peer();
        let peer_3 = default_peer();

        let intervals = [
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-5),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-3),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-2),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-1),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-0),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(1),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(2),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(3),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(5),
            },
        ];

        assert_eq!(
            find_interval(&intervals),
            Some((
                NtpDuration::from_fixed_int(-3),
                NtpDuration::from_fixed_int(3)
            ))
        );

        let survivors = construct_survivors(&intervals, NtpTimestamp::from_fixed_int(0));
        assert_eq!(survivors.len(), 3);
    }

    #[test]
    fn find_interval_no_consensus() {
        // Three disjoint intervals
        let peer_1 = default_peer();
        let peer_2 = default_peer();
        let peer_3 = default_peer();

        let intervals = [
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-4),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-3),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(-2),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-1),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-0),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(1),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(2),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(3),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(4),
            },
        ];

        assert_eq!(find_interval(&intervals), None);

        let survivors = construct_survivors(&intervals, NtpTimestamp::from_fixed_int(0));
        assert_eq!(survivors.len(), 0);
    }

    #[test]
    fn find_interval_tiling() {
        // Three intervals whose midpoints are not in any of the others
        // but which still overlap somewhat.
        let peer_1 = default_peer();
        let peer_2 = default_peer();
        let peer_3 = default_peer();

        let intervals = [
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-5),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-3),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-2),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(-1),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-0),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(1),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(2),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(3),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(5),
            },
        ];

        assert_eq!(find_interval(&intervals), None);

        let survivors = construct_survivors(&intervals, NtpTimestamp::from_fixed_int(0));
        assert_eq!(survivors.len(), 0);
    }
}
