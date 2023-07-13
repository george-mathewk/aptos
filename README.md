# Aptos Atomic Swaps and supporting Typescript app
Currently, the move-tests fail since event hadnles arent being initialized in any of the tests. You can compilet the move code using aptos move compile and run the tests using aptos move test when the directory is "atomicSwap_V5".

However, the typescript application does run, please comment out all but one of the function calls (initialize, redeem or refund) and you can see the details of the same. You can run this using ts-node as - npm ts-node src/index.ts when the current directory is "Typescript-App".
