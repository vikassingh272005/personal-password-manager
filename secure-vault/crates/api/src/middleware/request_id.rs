use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};

pub fn request_id_layer() -> (
    SetRequestIdLayer<MakeRequestUuid>,
    PropagateRequestIdLayer,
) {
    (
        SetRequestIdLayer::x_request_id(MakeRequestUuid),
        PropagateRequestIdLayer::x_request_id(),
    )
}
