//! # CTF (Capture-the-Flag) Pallet
//!
//! A pallet implementing a Capture-the-Flag game with proof-of-work challenges.
//! Players solve PoW challenges to earn on-chain points.
//!
//! ## Overview
//!
//! This pallet demonstrates:
//! - Custom proof-of-work validation using the system account nonce
//! - Score tracking for players
//! - Withdrawal mechanism that disables future submissions
//! - Lottery system
//!
//! The pallet contains deliberate vulnerabilities for educational purposes,

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame::pallet(dev_mode)]
pub mod pallet {
    use frame::{
        hashing::{blake2_256, U256},
        prelude::*,
    };
    use sp_runtime::RuntimeDebug;
    use sp_std::prelude::*;

    /// Configure the pallet by specifying the parameters and types on which it depends.
    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Enum to track player score state
    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, MaxEncodedLen, TypeInfo)]
    pub enum ScoreState {
        /// Player has enabled score with current point total
        Enabled(u64),
        /// Player has withdrawn and is disabled from future submissions
        Disabled,
    }

    impl Default for ScoreState {
        fn default() -> Self {
            ScoreState::Enabled(0)
        }
    }

    /// Storage for player scores
    #[pallet::storage]
    pub type Score<T: Config> = StorageMap<_, Twox128, T::AccountId, ScoreState, ValueQuery>;

    /// Storage for lottery entries
    #[pallet::storage]
    pub type LotteryEntries<T: Config> = StorageMap<_, Twox64Concat, T::AccountId, (), OptionQuery>;

    /// Storage for lottery entry count
    #[pallet::storage]
    pub type LotteryEntryCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Storage for lottery randomness
    #[pallet::storage]
    pub type LotteryRandomness<T: Config> = StorageValue<_, H256, OptionQuery>;

    /// The pallet's events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A solution was accepted
        SolutionAccepted {
            who: T::AccountId,
            difficulty: u32,
            new_score: u64,
        },
        /// A player has withdrawn their points
        Withdrawn { who: T::AccountId, points: u64 },
        /// A lottery entry was added
        LotteryEntryAdded {
            who: T::AccountId,
            entry_number: u32,
        },
        /// A lottery winner was selected
        LotteryWinnerSelected {
            who: T::AccountId,
            points_awarded: u64,
        },
    }

    /// The pallet's errors
    #[pallet::error]
    pub enum Error<T> {
        /// The provided proof is invalid
        BadProof,
        /// The difficulty value is invalid
        InvalidDifficulty,
        /// The account has already withdrawn
        AlreadyWithdrawn,
        /// The account's score is disabled
        ScoreDisabled,
        /// The difficulty is not exactly 25 for lottery entry
        InvalidLotteryDifficulty,
        /// Failed to add lottery entry
        LotteryEntryFailed,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(n: BlockNumberFor<T>) -> Weight {
            let current_randomness = LotteryRandomness::<T>::get();
            let block_number_bytes = n.encode();

            let new_randomness = current_randomness.map(|rand| {
                let mut input = Vec::new();
                input.extend_from_slice(rand.as_ref());
                input.extend_from_slice(&block_number_bytes);
                H256::from(blake2_256(&input))
            });

            LotteryRandomness::<T>::mutate(|rand| *rand = new_randomness);

            if LotteryEntryCount::<T>::get() >= 20 {
                let _ = Self::select_lottery_winner();
            }

            Weight::zero()
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit a solution to the PoW challenge
        #[pallet::call_index(0)]
        #[pallet::weight(100_000_000)]
        pub fn submit_solution(
            origin: OriginFor<T>,
            difficulty: u32,
            work: T::Hash,
        ) -> DispatchResult {
            // Check that the extrinsic was signed and get the signer
            let who = ensure_signed(origin)?;

            // Ensure difficulty is within valid range
            ensure!(
                (20..=256).contains(&difficulty),
                Error::<T>::InvalidDifficulty
            );

            // Get the current score state
            let score_state = Score::<T>::get(&who);

            // Ensure account is not disabled
            if score_state == ScoreState::Disabled {
                return Err(Error::<T>::ScoreDisabled.into());
            }

            let tx_nonce = frame_system::Pallet::<T>::account_nonce(&who);
            let tx_nonce: u32 = tx_nonce.try_into().map_err(|_| Error::<T>::BadProof)?;
            // Verify the proof-of-work
            let is_valid = Self::verify_pow(&who, tx_nonce, difficulty, &work)?;
            ensure!(is_valid, Error::<T>::BadProof);

            // Update the player's score
            let mut points = match score_state {
                ScoreState::Enabled(pts) => pts,
                _ => 0,
            };

            let added = 1u64 << (difficulty - 20);
            points = points.saturating_add(added);

            // Update the storage
            Score::<T>::insert(&who, ScoreState::Enabled(points));

            // Emit an event
            Self::deposit_event(Event::SolutionAccepted {
                who,
                difficulty,
                new_score: points,
            });

            Ok(())
        }

        /// Withdraw points and disable the account from future submissions
        #[pallet::call_index(1)]
        #[pallet::weight(100_000_000)]
        pub fn withdraw(origin: OriginFor<T>) -> DispatchResult {
            // Check that the extrinsic was signed and get the signer
            let who = ensure_signed(origin)?;

            // Get the current score state
            let score_state = Score::<T>::get(&who);

            // Ensure account is not already disabled
            match score_state {
                ScoreState::Disabled => return Err(Error::<T>::AlreadyWithdrawn.into()),
                ScoreState::Enabled(points) => {
                    // Set the account state to Disabled
                    Score::<T>::insert(&who, ScoreState::Disabled);

                    // Emit an event
                    Self::deposit_event(Event::Withdrawn { who, points });

                    Ok(())
                }
            }
        }

        /// Enter the lottery with a proof-of-work of difficulty 25
        #[pallet::call_index(2)]
        #[pallet::weight(100_000_000)]
        pub fn enter_lottery(origin: OriginFor<T>, work: T::Hash) -> DispatchResult {
            // Check that the extrinsic was signed and get the signer
            let who = ensure_signed(origin)?;

            // Get the current score state
            let score_state = Score::<T>::get(&who);

            // Ensure account is not disabled
            if score_state == ScoreState::Disabled {
                return Err(Error::<T>::ScoreDisabled.into());
            }

            // Fixed difficulty of 25 for lottery entry
            let difficulty = 25u32;

            let tx_nonce = frame_system::Pallet::<T>::account_nonce(&who);
            let tx_nonce: u32 = tx_nonce.try_into().map_err(|_| Error::<T>::BadProof)?;

            // Verify the proof-of-work
            let is_valid = Self::verify_pow(&who, tx_nonce, difficulty, &work)?;
            ensure!(is_valid, Error::<T>::BadProof);

            // Add to lottery
            Self::add_lottery_entry(who)?;

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Add a lottery entry for the account
        fn add_lottery_entry(who: T::AccountId) -> DispatchResult {
            // Get the current entry count
            let entry_count = LotteryEntryCount::<T>::get();

            // Check if the account has already been added
            if LotteryEntries::<T>::contains_key(&who) {
                return Err(Error::<T>::LotteryEntryFailed.into());
            }

            // Add the entry to the lottery
            LotteryEntries::<T>::insert(&who, ());

            // Increment the entry count
            let new_entry_count = entry_count.saturating_add(1);
            LotteryEntryCount::<T>::put(new_entry_count);

            // Emit an event for the new entry
            Self::deposit_event(Event::LotteryEntryAdded {
                who: who.clone(),
                entry_number: entry_count,
            });
            Ok(())
        }

        /// Select a lottery winner
        fn select_lottery_winner() -> DispatchResult {
            let randomness = LotteryRandomness::<T>::get();

            // Get the entry count
            let entry_count = LotteryEntryCount::<T>::get();

            let winner_index = randomness
                .map(|rand| {
                    // Convert hash to a number and take modulo of entry count
                    let rand_bytes = rand.as_ref();
                    let rand_number = u32::from_be_bytes([
                        rand_bytes[0],
                        rand_bytes[1],
                        rand_bytes[2],
                        rand_bytes[3],
                    ]);
                    rand_number % entry_count
                })
                .unwrap_or_default();

            // Iterate through the entries and find the winner
            let mut winner: Option<T::AccountId> = None;
            let mut iter = LotteryEntries::<T>::iter();
            for i in 0..entry_count {
                if let Some((entry, _)) = iter.next() {
                    if i == winner_index {
                        winner = Some(entry);
                    } else {
                        LotteryEntries::<T>::remove(entry);
                    }
                }
            }
            if let Some(winner) = winner {
                // Calculate the points to award
                let points_to_award = 25u64 * (1 << 5);

                // Update the winner's score
                let score_state = Score::<T>::get(&winner);
                let current_points = match score_state {
                    ScoreState::Enabled(pts) => pts,
                    _ => return Err(Error::<T>::AlreadyWithdrawn.into()),
                };

                let new_points = current_points.saturating_add(points_to_award);
                Score::<T>::insert(&winner, ScoreState::Enabled(new_points));

                // Emit an event
                Self::deposit_event(Event::LotteryWinnerSelected {
                    who: winner,
                    points_awarded: points_to_award,
                });
            }

            // Reset the lottery
            LotteryEntryCount::<T>::put(0u32);

            Ok(())
        }

        /// Verify the proof-of-work
        fn verify_pow(
            who: &T::AccountId,
            nonce: u32,
            difficulty: u32,
            work: &T::Hash,
        ) -> Result<bool, Error<T>> {
            // Convert input values to bytes for hashing
            let who_bytes = who.encode();
            let nonce_bytes = nonce.encode();
            let difficulty_bytes = difficulty.encode();
            let work_bytes = work.as_ref();

            // Concatenate the bytes
            let mut input = Vec::new();
            input.extend_from_slice(&who_bytes);
            input.extend_from_slice(&nonce_bytes);
            input.extend_from_slice(&difficulty_bytes);
            input.extend_from_slice(work_bytes);

            log::info!("input: {:?}", input);

            // Calculate the hash
            let hash = sp_io::hashing::blake2_256(&input);

            log::info!("hash: {:?}", hash);

            // Convert the hash to a numeric value for comparison
            let hash_value = U256::from_little_endian(&hash);

            log::info!("hash_value: {:?}", hash_value);

            // Calculate the target value: 2^256 / 2^difficulty
            // This simplifies to 2^(256-difficulty)
            let target = if difficulty < 256 {
                U256::one() << (256 - difficulty)
            } else {
                U256::one() // If difficulty=256, target=1 (nearly impossible)
            };

            // The proof is valid if the hash value is less than the target
            Ok(hash_value < target)
        }
    }
}
