import { SHA256 } from 'crypto-js';
import { TextEncoder } from 'util';
import axios from 'axios';
import { AptosAccount, AptosClient, HexString, FaucetClient } from "aptos";
import { randomBytes } from "crypto";
import { sha256 } from 'ethers';
import { expect } from 'chai';
import {describe, it} from 'mocha'

const NODE_URL = "https://fullnode.devnet.aptoslabs.com";
const FAUCET_URL = "https://faucet.devnet.aptoslabs.com";  

const textEncoder = new TextEncoder();


class atomicSwapClient extends AptosClient {
  constructor() {
    super(NODE_URL);
  }

  /** Deploy Event Handles **/
  async deployHandles(atomicContract: AptosAccount): Promise<string> {

    const rawTxn = await this.generateTransaction(atomicContract.address(), {
      function: `${atomicContract.address()}::AtomicSwap::deployEventHandles`,
      type_arguments: [],
      arguments: [],
    });

    const bcsTxn = await this.signTransaction(atomicContract, rawTxn);
    const pendingTxn = await this.submitTransaction(bcsTxn);

    return pendingTxn.hash;
  }

  /** Starts the Swap **/
  async startSwap(
    atomicContractAddress: HexString,
    sender: AptosAccount,
    reciever: HexString,
    amount: number,
    secret_hash: any,
    expiry: number,
    type: string
  ): Promise<string> {

    const rawTxn = await this.generateTransaction(sender.address(), {
      function: `${atomicContractAddress}::AtomicSwap::initialize_Swap`,
      type_arguments: [type],
      arguments: [reciever.hex(), secret_hash, amount, expiry, atomicContractAddress],
    });

    const bcsTxn = await this.signTransaction(sender, rawTxn);
    const pendingTxn = await this.submitTransaction(bcsTxn);

    return pendingTxn.hash;
  }

  // Redeem the Swap
  async redeemSwap(
    atomicContractAddress: HexString,
    sender: HexString, 
    reciever: AptosAccount, 
    secret: any,
    type: string
  ): Promise<string> {
    const rawTxn = await this.generateTransaction(reciever.address(), {
      function: `${atomicContractAddress}::AtomicSwap::redeem_Swap`,
      type_arguments: [type],
      arguments: [sender.hex(), reciever.address().hex(), secret, atomicContractAddress],
    });

    const bcsTxn = await this.signTransaction(reciever, rawTxn);
    const pendingTxn = await this.submitTransaction(bcsTxn);

    console.log("Initiating Redeem");
    return pendingTxn.hash;
  }

  // Refund the Swap
  async refundSwap(
    atomicContractAddress: HexString,
    reciever: AptosAccount,
    sender: HexString,
    type: string
  ): Promise<string> {
    const rawTxn = await this.generateTransaction(reciever.address(), {
      function: `${atomicContractAddress}::AtomicSwap::refund_Swap`,
      type_arguments: [type],
      arguments: [sender.hex(), reciever.address().hex(), atomicContractAddress],
    });

    const bcsTxn = await this.signTransaction(reciever, rawTxn);
    const pendingTxn = await this.submitTransaction(bcsTxn);
    
    console.log("Initiating Refund");
    return pendingTxn.hash;
  }

  // =============================================== View Functions ===============================================  
  async getResourceAddress(
    atomicContractAddress: HexString,
    sender: HexString,
    reciever: HexString
  ): Promise<any[]> {
    const payload: any = {
        function: `${atomicContractAddress}::AtomicSwap::getAtomicAddress`,
        type_arguments: [],
        arguments: [sender.hex(), reciever.hex()],
    };

    return await this.view(payload);
  }

  async getStoredHash(
    atomicContractAddress: HexString,
    sender: HexString, 
    reciever: HexString,
    type: string
  ): Promise<any[]> {
    const payload: any = {
        function: `${atomicContractAddress}::AtomicSwap::getStoredHash`,
        type_arguments: [type],
        arguments: [sender.hex(), reciever.hex()],
    };

    return await this.view(payload);
  }

  async returnHashed(
    atomicContractAddress: HexString,
    secret: string
  ): Promise<any[]> {
    const payload: any = {
        function: `${atomicContractAddress}::AtomicSwap::return_Hashed`,
        type_arguments: [],
        arguments: [secret],
    };

    return await this.view(payload);
  }

  async returnWhatHappens(
    atomicContractAddress: HexString,
    secret: Uint8Array
  ): Promise<any[]> {
    const payload: any = {
        function: `${atomicContractAddress}::AtomicSwap::return_What_Happens`,
        type_arguments: [],
        arguments: [secret],
    };

    return await this.view(payload);
  }

  async returnCheckIt(
    atomicContractAddress: HexString,
    secret: any,
    sender: HexString,
    reciever: HexString,
    type: string
  ): Promise<any[]> {
    const payload: any = {
        function: `${atomicContractAddress}::AtomicSwap::checkIfEqualV2`,
        type_arguments: [type],
        arguments: [secret, sender.hex(), reciever.hex()],
    };

    return await this.view(payload);
  }
}

function init(): [AptosAccount, AptosAccount, AptosAccount] {
  let privateModule = "0xd9a7475f484759cd32215cb76e398a0c090b5b843a0461220cc61fbebe115f02";
  let privateModuleBytes = HexString.ensure(privateModule).toUint8Array();

  let privateSender = "0xf1db30c99b1518ab5e19066ad5aaf6f7c8bf5e3cb72fa4e125db2b9dca421a2d";
  let privateSenderBytes = HexString.ensure(privateSender).toUint8Array();

  let privateReciever = "0x9a48986fbb5d5f0f8d273afd46e13f6e3b0649498a2bef1b7020f526e6eb9f19";
  let privateRecieverBytes = HexString.ensure(privateReciever).toUint8Array();

  const module = new AptosAccount(
    privateModuleBytes,
    "0x12a55344166c08cbd24db1b20f4548ce1e201c198252736d16c8944309df0135"
  )

  const sender = new AptosAccount(
    privateSenderBytes,
    "0xc14e394b8aab31ecbd4d1590404cb898473c93eac82b9945f9b395e17d557c41"
  );
  const reciever = new AptosAccount(
    privateRecieverBytes,
    "c563fa7c7baa3b24830987245ea7c6d9239eec3f9a2bd6dcb24d3b9c00eda812"
  );

  return [module, sender, reciever]
}

function contractTo1Digit(inp: Uint8Array){
  let ret: number[] = [];
  for(let i = 0; i < inp.length; i += 2){
    ret.push(inp[i]*16 + inp[i+1]);
  }

  return Uint8Array.from(ret)
}

function hashSecret(inp: any){
  let secret_hash = SHA256(inp);
  let encoded = textEncoder.encode(secret_hash);
  let after = Uint8Array.from(encoded.map(value => value < 96 ? value - 48 : value - 87));
  let next = contractTo1Digit(after);

  return next;
}

async function eventsAPICAll(apiBase: string, eventHandle: string) {
    let ret = [];
    await axios.get(`${apiBase}${eventHandle}`)
    .then(response => {
      // console.log(response.data[response.data.length - 1]); // Process the received data
      ret = response.data;
    })
    .catch(error => {
      console.error('Error:', error);
    });
    return ret;
}

/** run our demo! */
async function main() {

describe("Test",  () => {
    it("test test", async ()=>{

    
  const fromHexString = (hexString) =>
  Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

  const client = new atomicSwapClient();
  const faucetClient = new FaucetClient(NODE_URL, FAUCET_URL);

  const apt = '0x1::aptos_coin::AptosCoin';


  let secret = randomBytes(32);
  let secret_hash = hashSecret(secret.toString());
  console.log(`sha256 from ethers: ${sha256(secret).slice(2)}`);

  // const secret: string = "ABAB";
  // let secret_hash = hashSecret(secret);
  // let secret_hash_uint8 = textEncoder.encode(secret_hash);

  const [module, sender, reciever] = init();
  let apiCall = `https://fullnode.devnet.aptoslabs.com/v1/accounts/${module.address()}/events/${module.address()}::AtomicSwap::EventHandles/`;

//   await faucetClient.fundAccount(sender.address(), 100_000_000);
//   await faucetClient.fundAccount(reciever.address(), 100_000_000);

  console.log(`Deploying event handles at ${module.address()}`);
  let txnHash = await client.deployHandles(module);
  await client.waitForTransaction(txnHash, { checkSuccess: true });
  console.log(`Deployed Handles!`);
  
  
  console.log(`Sender initializes a swap with secret:`);
  console.log(secret.toString("hex"));
  txnHash = await client.startSwap(module.address(), sender, reciever.address(), 20000, fromHexString(sha256(secret).slice(2)), 1, apt);
  await client.waitForTransaction(txnHash, { checkSuccess: true });
  console.log("initialized\nCheck Events:");
  eventsAPICAll(apiCall, 'initialize_events');
  
  let add = await client.getResourceAddress(module.address(), sender.address(), reciever.address());
  console.log(`resource account address:    ${add}`);

  // add = await client.returnWhatHappens(module.address(), new Uint8Array(secret));
  // console.log(`What Happens:           ${add}`);

  add = await client.getStoredHash(module.address(), sender.address(), reciever.address(), apt);
  console.log(`\nStored Hash:                 ${add}`);

  add = await client.returnCheckIt(module.address(), secret.toString("hex"), sender.address(), reciever.address(), apt);
  console.log(`Returned Check  :            ${add}`);
    
  // let txnHash = await client.refundSwap(module.address(), reciever, sender.address(), apt);
  // await client.waitForTransaction(txnHash, { checkSuccess: true });
  // console.log('refunded check events: ');
  // eventsAPICAll(apiCall, 'refund_events');

  txnHash = await client.redeemSwap(module.address(), sender.address(), reciever, secret, apt); 
  await client.waitForTransaction(txnHash, { checkSuccess: true });
  console.log('redeemed check events: ');
  let evs = await eventsAPICAll(apiCall, 'redeem_events');
  console.log(evs[evs.length - 1].data.secret.slice(2));
    })
  
  // await client.waitForTransaction(txnHash, { checkSuccess: true });
})

}

main()
  .then(() => {
    // console.log('Main function completed.');
  })
  .catch((error) => {
    console.error('An error occurred:', error);
});