module Atomic_Swap::AtomicSwap {
    #[test_only]
    use std::unit_test;
    #[test_only]
    use 0x1::aptos_coin;
    // #[test_only]
    #[test_only]
    use 0x1::aptos_coin::AptosCoin;

    // use 0x1000000fa32d122c18a6a31c009ce5e71674f22d06a581bb0a15575e6addadcc::AptosCoin::AptosCoin;
    use 0x1::string;                // For checking the secret against stored hash
    use 0x1::signer;                // To perform signer::address_of()
    use 0x1::hash;                  // To perform sha2_256()
    use 0x1::aptos_account;         // To perform transfers
    // use 0x1::aptos_coin::AptosCoin; // Type for APT
    use 0x1::coin;                  // To get balance
    use 0x1::bcs;                   // To convert address to bytes
    use 0x1::account;               // To retrieve resource address later
    use 0x1::timestamp;             // To set and check expiry
    use 0x1::event;                 // For the events
    use 0x1::vector;                // To make empty vectors

    const ENOT_ENOUGH_FUNDS: u64 = 0;
    const ESECRET_MISMATCH: u64 = 1;
    const ESWAP_ALREADY_EXISTS: u64 = 2;
    const ESWAP_DOESNT_EXIST: u64 = 3;
    const EWRONG_STATUS: u64 = 4;
    const EWRONG_BALANCE: u64 = 5;
    const ENO_DEPLOYING_SIGNER_CAPABILITY: u64 = 6;
    const EINVALID_DEPLOYER: u64 = 7;
    const ESIGNING_STRUCT_DOESNT_EXIST: u64 = 8;    
    const ENOT_EXPIRED: u64 = 9;
    const EEXPIRED: u64 = 10;
    const EEVENT_HANDLES_DONT_EXIST: u64 = 11;
    
    struct Swap<phantom CoinType> has key{
        sender: address,
        reciever: address,
        amount: u64,
        secret_hash: vector<u8>,
        coins: coin::Coin<CoinType>,
        expiry: u64,
    }

    struct DeployerSignCap has key{
        signer_capability: account::SignerCapability,
        deployer: address,
    }

    struct EventHandles has key {
        initialize_events: event::EventHandle<InitializeEvent>,
        refund_events: event::EventHandle<RefundEvent>,
        redeem_events: event::EventHandle<RedeemEvent>,
    }

    struct InitializeEvent has drop, store{
        sender: address,
        reciever: address
    }

    struct RefundEvent has drop, store{
        sender: address,
        reciever: address
    }

    struct RedeemEvent has drop, store{
        sender: address,
        reciever: address,
        secret: vector<u8>
    }


    // Initialize Swap and generate initialize_Event
    public entry  fun initialize_Swap<CoinType>(
        sender_signer: signer,
        reciever: address,
        secret_hash: vector<u8>,
        amount: u64, 
        expiry_hours: u64,
        event_address: address
    ) acquires DeployerSignCap, EventHandles{
        // Get the address from the signer
        let sender = signer::address_of(&sender_signer);
        
        // Checks if enough funds
        assert!(
            coin::balance<CoinType>(sender) >= amount,
            ENOT_ENOUGH_FUNDS
        );

        // Create Swap struct object and puts the coins into it
        let swap = Swap{
            sender: sender,
            reciever: copy reciever,
            amount: amount,
            // secret_hash: *string::bytes(&secret_hash),
            secret_hash: secret_hash,
            coins: coin::withdraw<CoinType>(&sender_signer, amount),
            expiry: timestamp::now_seconds() + expiry_hours * 60
        };

        // Converts the reciever address to the seed for the resource account
        let seed = bcs::to_bytes<address>(&reciever);

        let atomic_address = account::create_resource_address(&sender, seed);

        let atomic_signer = 
            if(!account::exists_at(atomic_address)){
                // Creates the resource account
                let (temp, signer_capability) = account::create_resource_account(
                    &sender_signer,
                    seed
                );
                
                return_Signing_Capablity(
                    sender,
                    &temp,
                    signer_capability
                );

                temp
            } else {
                get_Signer(
                    sender,
                    atomic_address
                )
            };

        
        // Makes sure swap doesn't already exist at atomic_address
        assert!(
            !exists<Swap<CoinType>>(atomic_address),
            ESWAP_ALREADY_EXISTS
        );

        // Moves struct swap to sender account 
        move_to<Swap<CoinType>>(&atomic_signer, swap);

        // Create the init swap event 
        let init_Event = InitializeEvent {
            sender: sender,
            reciever: reciever
        };

        // Check that event handles object exists
        assert!(
            exists<EventHandles>(event_address),
            EEVENT_HANDLES_DONT_EXIST
        );

        // Emit the event
        event::emit_event<InitializeEvent>(
            &mut borrow_global_mut<EventHandles>(event_address).initialize_events,
            init_Event,
        );
    }

    // Redeem Swap and emit a redeem_Event
    public entry  fun redeem_Swap<CoinType>(
        sender_address: address,
        reciever_address: address,
        secret: vector<u8>,
        event_address: address
    ) acquires Swap, EventHandles{
        // Converts the reciever address to the seed for the resource account
        let seed = bcs::to_bytes<address>(&reciever_address);

        // Gets the address of the resource account
        let atomic_address = account::create_resource_address(&sender_address, seed);

        // Makes sure swap was initialized in the sender
        assert!(
            exists<Swap<CoinType>>(atomic_address),
            ESWAP_DOESNT_EXIST
        );

        // Gets a mutable reference to the swap object in sender
        let Swap{
            sender: _,
            reciever,
            amount: _,
            secret_hash,
            coins,
            expiry
        } = move_from<Swap<CoinType>>(atomic_address);

        // Check that hashed secret is same as swap.secret_hash
        assert!(
            // secret_hash == hash::sha2_256(*string::bytes(&secret)),
            secret_hash == hash::sha2_256(secret),
            ESECRET_MISMATCH
        );

        // Check that its not expired
        assert!(timestamp::now_seconds() < expiry, EEXPIRED);

        // Transfers the stipulated amount to the reciever
        aptos_account::deposit_coins<CoinType>(reciever, coins);

        // Create the refund swap event 
        let init_Event = RedeemEvent {
            sender: sender_address,
            reciever: reciever_address,
            secret: copy secret
        };

        // Check that event handles object exists
        assert!(
            exists<EventHandles>(event_address),
            EEVENT_HANDLES_DONT_EXIST
        );

        // Emit the event
        event::emit_event<RedeemEvent>(
            &mut borrow_global_mut<EventHandles>(event_address).redeem_events,
            init_Event,
        );
    }

    // Refund swap and emit a refund_event
    public entry fun refund_Swap<CoinType>(
        sender_address: address,
        reciever_address: address,
        event_address: address
    ) acquires Swap, EventHandles {
        // Converts the reciever address to the seed for the resource account
        let seed = bcs::to_bytes<address>(&reciever_address);

        // Gets the address of the resource account
        let atomic_address = account::create_resource_address(&sender_address, seed);

        // Makes sure swap was initialized in the sender
        assert!(
            exists<Swap<CoinType>>(atomic_address),
            ESWAP_DOESNT_EXIST
        );

        // Gets a mutable reference to the swap object in sender
        let Swap{
            sender,
            reciever: _,
            amount: _,
            secret_hash: _,
            coins,
            expiry,
        } = move_from<Swap<CoinType>>(atomic_address);
        
        assert!(
            timestamp::now_seconds() >= expiry,
            ENOT_EXPIRED
        );

        // Transfers the stipulated amount to the reciever
        aptos_account::deposit_coins<CoinType>(sender, coins);

        // Create the redeem swap event 
        let init_Event = RefundEvent {
            sender: sender_address,
            reciever: reciever_address
        };

        // Check that event handles object exists
        assert!(
            exists<EventHandles>(event_address),
            EEVENT_HANDLES_DONT_EXIST
        );

        // Emit the event
        event::emit_event<RefundEvent>(
            &mut borrow_global_mut<EventHandles>(event_address).refund_events,
            init_Event,
        );
    }

    public entry fun deployEventHandles(
        contractSigner: &signer
    ) {
        if(!exists<EventHandles>(signer::address_of(contractSigner))) {
            let eventHandles = EventHandles {
                initialize_events: account::new_event_handle<InitializeEvent>(contractSigner),
                refund_events: account::new_event_handle<RefundEvent>(contractSigner),
                redeem_events: account::new_event_handle<RedeemEvent>(contractSigner),
            };

            move_to<EventHandles>(contractSigner, eventHandles);
        }
    }

    public fun get_Signer(
        sender: address,
        resource: address
    ): signer acquires DeployerSignCap {
        let (signer_cap) = get_Signing_Capability(
            sender,
            resource
        );
        let sig = account::create_signer_with_capability(&signer_cap);
        return_Signing_Capablity(
            sender,
            &sig,
            signer_cap
        ); 
        sig
    }

    public fun get_Signing_Capability(
        sender: address,
        resource: address
    ): account::SignerCapability
    acquires DeployerSignCap{
        assert!(exists<DeployerSignCap>(resource), ENO_DEPLOYING_SIGNER_CAPABILITY);
        let DeployerSignCap {
            signer_capability,
            deployer,
            } = move_from<DeployerSignCap>(resource);
        assert!(sender == deployer, EINVALID_DEPLOYER);
        signer_capability
    }

    public fun return_Signing_Capablity(
        deployer: address,
        resource_signer: &signer,
        resource_signer_cap: account::SignerCapability
    ){
        let deployerSignCap = DeployerSignCap{
            signer_capability: resource_signer_cap,
            deployer: deployer,
        };

        move_to<DeployerSignCap>(resource_signer, deployerSignCap);
    }

    #[view]
    public fun getAtomicAddress(sender_address: address, reciever_address: address): address {
        let seed = bcs::to_bytes<address>(&reciever_address);
        account::create_resource_address(&sender_address, seed)
    }

    #[view]
    public fun getStoredHash<CoinType: key>(sender_address: address, reciever_address: address): vector<u8> acquires Swap {
        let seed = bcs::to_bytes<address>(&reciever_address);
        let add = account::create_resource_address(&sender_address, seed);
        borrow_global<Swap<CoinType>>(add).secret_hash
    }

    #[view]
    public fun getStoredHashLength<CoinType: key>(sender_address: address, reciever_address: address): u64 acquires Swap {
        let seed = bcs::to_bytes<address>(&reciever_address);
        let add = account::create_resource_address(&sender_address, seed);
        vector::length<u8>(&borrow_global<Swap<CoinType>>(add).secret_hash)
    }

    #[view]
    public fun return_Hashed(inp: string::String): vector<u8> {
        hash::sha2_256(*string::bytes(&inp) ) 
    }

    #[view]
    public fun return_HashedV2(inp: vector<u8>): vector<u8> {
        hash::sha2_256(inp)
    }

    #[view]
    public fun return_What_Happens(inp: vector<u8>): vector<u8> {
        inp
    }

    #[view]
    public fun checkIfEqualV2<CoinType: key>(inp: vector<u8>, sender_address: address, reciever_address: address): bool acquires Swap {
        hash::sha2_256(inp) == getStoredHash<CoinType>(sender_address, reciever_address)
    }

    #[view]
    public fun checkIfEqual<CoinType: key>(inp: string::String, sender_address: address, reciever_address: address): bool acquires Swap {
        return_Hashed(inp) == getStoredHash<CoinType>(sender_address, reciever_address)
    }

    #[test_only]
    fun get_account(): (signer, signer) {
        let signers = unit_test::create_signers_for_testing(2);
        (vector::pop_back(&mut signers), vector::pop_back(&mut signers))
    }

    #[test_only]
    public fun init_account(add: address){
        if(!account::exists_at(add)){
            account::create_account_for_test(add);
        }
    }

    #[test_only]
    public fun setup_accounts_for_test(): (address, signer, address, signer, address){
        let (sender_signer, reciever_signer) = get_account();
        let sender_address = signer::address_of(&sender_signer);
        let reciever_address = signer::address_of(&reciever_signer);

        init_account(sender_address);
        init_account(reciever_address);

        let seed = bcs::to_bytes<address>(&reciever_address);
        let atomic_address = account::create_resource_address(&sender_address, seed);

        (sender_address, sender_signer, reciever_address, reciever_signer, atomic_address)
    } 

    #[test_only]
    public fun test_Initialization(framework: signer, expiry: u64):
        (address, address, address, vector<u8>, u64, u64, signer) acquires DeployerSignCap, EventHandles{
        let (sender_address, sender_signer, reciever_address, _, atomic_address) = setup_accounts_for_test();

        deployEventHandles(&sender_signer);

        let (aptos_coin_burn_cap, aptos_coin_mint_cap) = aptos_coin::initialize_for_test(&framework);

        let initial_bal: u64 = 100;

        // Start timestamp
        timestamp::set_time_has_started_for_testing(&framework);

        // Deposit into sender
        aptos_account::deposit_coins<AptosCoin>(
            sender_address,
            coin::mint(initial_bal, &aptos_coin_mint_cap)
        );
        // Deposit into reciever
        aptos_account::deposit_coins<AptosCoin>(
            reciever_address,
            coin::mint(initial_bal, &aptos_coin_mint_cap)
        );

        // Check that balance is correct for sender
        assert!(
            coin::balance<AptosCoin>(sender_address) == initial_bal,
            EWRONG_BALANCE
        );
        // Check that balance is correct for reciever
        assert!(
            coin::balance<AptosCoin>(reciever_address) == initial_bal,
            EWRONG_BALANCE
        );
        // debug::print<u64>(&coin::balance<AptosCoin>(sender_address));

        let secret = b"ABABAB";
        let secret_hash = hash::sha2_256(secret);
        let amount = 1;

        initialize_Swap<AptosCoin>(
            sender_signer,
            reciever_address,
            secret_hash,
            amount, 
            expiry,
            sender_address
        );
        
        // Check that swap exists
        assert!(
            exists<Swap<AptosCoin>>(atomic_address),
            ESWAP_DOESNT_EXIST
        );
        // Check that DeploySigner exists
        assert!(
            exists<DeployerSignCap>(atomic_address),
            ESIGNING_STRUCT_DOESNT_EXIST
        );
        // Check that sender balance is correct
        assert!(
            coin::balance<AptosCoin>(sender_address) == initial_bal - amount,
            EWRONG_BALANCE
        );

        coin::destroy_mint_cap<AptosCoin>(aptos_coin_mint_cap);
        coin::destroy_burn_cap<AptosCoin>(aptos_coin_burn_cap);

        (sender_address, reciever_address, atomic_address, secret, initial_bal, amount, framework)
    }

    
    #[test(framework = @aptos_framework)]
    public fun test_Basic(framework: signer) acquires DeployerSignCap, EventHandles {
        test_Initialization(framework, 0);
    }

    #[test(framework = @aptos_framework)]
    public fun test_Redeem_Correct_Secret(framework: signer) acquires DeployerSignCap, Swap, EventHandles{
        let (sender_address, reciever_address, atomic_address, secret, initial_bal, amount, _)
            = test_Initialization(framework, 1);

        redeem_Swap<AptosCoin>(
            sender_address,
            reciever_address,
            secret,
            sender_address
        );

        // Check Swap exists
        assert!(
            !exists<Swap<AptosCoin>>(atomic_address),
            ESWAP_ALREADY_EXISTS
        );
        // Check balance is correct
        assert!(
            coin::balance<AptosCoin>(reciever_address) == initial_bal + amount,
            EWRONG_BALANCE
        );
    }

    #[test(framework = @aptos_framework)]
    #[expected_failure(abort_code = ESECRET_MISMATCH)]
    public fun test_Redeem_Incorrect_Secret(framework: signer) acquires DeployerSignCap, Swap, EventHandles{
        let (sender_address, reciever_address, _, _, _, _, _)
            = test_Initialization(framework, 1);
        
        // Expect redeem to fail
        redeem_Swap<AptosCoin>(
            sender_address,
            reciever_address,
            b"ASDSADASD",
            sender_address
        );
    }

    #[test(framework = @aptos_framework)]
    public fun test_Refund(framework: signer) acquires DeployerSignCap, Swap, EventHandles{
        let (sender_address, reciever_address, atomic_address, _, initial_bal, _, _)
            = test_Initialization(framework, 0);

        refund_Swap<AptosCoin>(
            sender_address,
            reciever_address,
            sender_address
        );

        // Check Swap exists
        assert!(
            !exists<Swap<AptosCoin>>(atomic_address),
            ESWAP_ALREADY_EXISTS
        );
        // Check balance is correct
        assert!(
            coin::balance<AptosCoin>(sender_address) == initial_bal,
            EWRONG_BALANCE
        );
    }

    #[test(framework = @aptos_framework)]
    #[expected_failure(abort_code = ESWAP_DOESNT_EXIST)]
    public fun test_Redeem_After_Refund(framework: signer) acquires DeployerSignCap, Swap, EventHandles{
        let (sender_address, reciever_address, _, secret, _, _, _)
            = test_Initialization(framework, 0);
        
        // Expect redeem to fail
        refund_Swap<AptosCoin>(
            sender_address,
            reciever_address,
            sender_address
        );

        redeem_Swap<AptosCoin>(
            sender_address,
            reciever_address,
            secret,
            sender_address
        )
    }

    #[test(framework = @aptos_framework)]
    #[expected_failure(abort_code = ENOT_EXPIRED)]
    public fun test_Refund_Before_Expiry(framework: signer) acquires DeployerSignCap, Swap, EventHandles{
        let (sender_address, reciever_address, _, _, _, _, _)
            = test_Initialization(framework, 1);
        
        // Expect redeem to fail
        refund_Swap<AptosCoin>(
            sender_address,
            reciever_address,
            sender_address
        );
    }

    #[test(framework = @aptos_framework)]
    #[expected_failure(abort_code = EEXPIRED)]
    public fun test_Redeem_After_Expiry(framework: signer) acquires DeployerSignCap, Swap, EventHandles{
        let (sender_address, reciever_address, _, secret, _, _, _)
            = test_Initialization(framework, 0);
        
        // Expect redeem to fail
        redeem_Swap<AptosCoin>(
            sender_address,
            reciever_address,
            secret,
            sender_address
        );
    }

    #[test(framework = @aptos_framework)]
    #[expected_failure(abort_code = ESWAP_DOESNT_EXIST)]
    public fun test_Refund_After_Redeem(framework: signer) acquires DeployerSignCap, Swap, EventHandles{
        let (sender_address, reciever_address, _, secret, _, _, _)
            = test_Initialization(framework, 1);
        
        // Expect redeem to fail
        redeem_Swap<AptosCoin>(
            sender_address,
            reciever_address,
            secret,
            sender_address
        );

        refund_Swap<AptosCoin>(
            sender_address,
            reciever_address,
            sender_address
        );
    }
}
