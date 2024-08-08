use crate::data_types::Call;
use crate::data_types::Multicall2;

// todo: p2: consider moving to multicall2
// todo: p1: should we return a bytes or vec<u8> here?
pub fn encode_multicall(require_success: bool, calls: Vec<Call>) -> string {
    let function_signature = "tryAggregate";
    return Multicall2::abi_encode_function(function_signature, require_success, calls);
}
