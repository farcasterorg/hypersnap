//! Farcaster API compatible response types.
//!
//! These types match the Farcaster v2 API response schemas for compatibility
//! with existing Farcaster SDK clients.

use serde::{Deserialize, Serialize};

// === Core Objects ===

/// User object matching Farcaster v2 API schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub object: String,
    pub fid: u64,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub custody_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pfp_url: Option<String>,
    pub registered_at: String,
    pub profile: UserProfile,
    pub follower_count: u64,
    pub following_count: u64,
    pub verifications: Vec<String>,
    pub auth_addresses: Vec<AuthAddress>,
    pub verified_addresses: VerifiedAddresses,
    pub verified_accounts: Vec<VerifiedAccount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewer_context: Option<ViewerContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    /// Timestamp when the follow was created (only in followers/following responses)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub followed_at: Option<String>,
}

impl Default for User {
    fn default() -> Self {
        Self {
            object: "user".to_string(),
            fid: 0,
            username: String::new(),
            display_name: None,
            custody_address: String::new(),
            pfp_url: None,
            registered_at: String::new(),
            profile: UserProfile::default(),
            follower_count: 0,
            following_count: 0,
            verifications: Vec::new(),
            auth_addresses: Vec::new(),
            verified_addresses: VerifiedAddresses::default(),
            verified_accounts: Vec::new(),
            viewer_context: None,
            score: None,
            followed_at: None,
        }
    }
}

/// User profile with bio, location, and banner.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserProfile {
    pub bio: Bio,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<Banner>,
}

/// User bio.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Bio {
    pub text: String,
}

/// User location.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Location {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// User banner image.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Banner {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Authenticated address for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAddress {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
}

/// Verified addresses for a user.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifiedAddresses {
    pub eth_addresses: Vec<String>,
    pub sol_addresses: Vec<String>,
    pub primary: PrimaryAddress,
}

/// Primary verified address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrimaryAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eth_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sol_address: Option<String>,
}

/// Verified account on external platforms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedAccount {
    pub platform: String,
    pub username: String,
}

/// Viewer context showing relationship to the viewer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ViewerContext {
    pub following: bool,
    pub followed_by: bool,
    #[serde(default)]
    pub blocking: bool,
    #[serde(default)]
    pub blocked_by: bool,
}

/// Cast viewer context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CastViewerContext {
    pub liked: bool,
    pub recasted: bool,
}

/// Cast object matching Farcaster v2 API schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cast {
    pub object: String,
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_parent_url: Option<String>,
    pub parent_author: ParentAuthor,
    pub author: User,
    pub text: String,
    pub timestamp: String,
    pub embeds: Vec<Embed>,
    pub r#type: String,
    pub reactions: CastReactions,
    pub replies: CastReplies,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_hash: Option<String>,
    pub mentioned_profiles: Vec<User>,
    #[serde(default)]
    pub mentioned_profiles_ranges: Vec<TextRange>,
    #[serde(default)]
    pub mentioned_channels: Vec<ChannelDehydrated>,
    #[serde(default)]
    pub mentioned_channels_ranges: Vec<TextRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<Channel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewer_context: Option<CastViewerContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_channel_context: Option<ChannelUserContext>,
}

impl Default for Cast {
    fn default() -> Self {
        Self {
            object: "cast".to_string(),
            hash: String::new(),
            parent_hash: None,
            parent_url: None,
            root_parent_url: None,
            parent_author: ParentAuthor::default(),
            author: User::default(),
            text: String::new(),
            timestamp: String::new(),
            embeds: Vec::new(),
            r#type: "cast".to_string(),
            reactions: CastReactions::default(),
            replies: CastReplies::default(),
            thread_hash: None,
            mentioned_profiles: Vec::new(),
            mentioned_profiles_ranges: Vec::new(),
            mentioned_channels: Vec::new(),
            mentioned_channels_ranges: Vec::new(),
            channel: None,
            viewer_context: None,
            author_channel_context: None,
        }
    }
}

/// Parent author reference (just FID).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParentAuthor {
    pub fid: Option<u64>,
}

/// Text range for mention positions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TextRange {
    pub start: u32,
    pub end: u32,
}

/// Dehydrated channel reference (used in mentioned_channels).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelDehydrated {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
}

/// Channel user context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelUserContext {
    pub following: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// Embed in a cast.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Embed {
    Url { url: String },
    Cast { cast_id: CastId },
}

/// Cast ID reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CastId {
    pub fid: u64,
    pub hash: String,
}

/// Reaction counts for a cast.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CastReactions {
    pub likes_count: u64,
    pub recasts_count: u64,
    #[serde(default)]
    pub likes: Vec<ReactionUser>,
    #[serde(default)]
    pub recasts: Vec<ReactionUser>,
}

/// User who reacted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionUser {
    pub fid: u64,
    pub fname: String,
}

/// Reply count for a cast.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CastReplies {
    pub count: u64,
}

/// Channel information matching Farcaster v2 API schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub object: String,
    pub id: String,
    pub url: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub follower_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lead: Option<Box<User>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moderator_fids: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_cast_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewer_context: Option<ChannelUserContext>,
}

impl Default for Channel {
    fn default() -> Self {
        Self {
            object: "channel".to_string(),
            id: String::new(),
            url: String::new(),
            name: String::new(),
            image_url: None,
            parent_url: None,
            description: None,
            created_at: String::new(),
            follower_count: None,
            member_count: None,
            lead: None,
            moderator_fids: None,
            pinned_cast_hash: None,
            viewer_context: None,
        }
    }
}

/// Pagination cursor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextCursor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

// === Response Types ===

/// Response for followers/following endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowersResponse {
    pub users: Vec<User>,
    pub next: NextCursor,
}

/// Response for feed endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedResponse {
    pub casts: Vec<Cast>,
    pub next: NextCursor,
}

/// Response for cast search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CastsSearchResponse {
    pub result: CastsSearchResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CastsSearchResult {
    pub casts: Vec<Cast>,
    pub next: NextCursor,
}

/// Response for single channel lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelResponse {
    pub channel: Channel,
}

/// Response for channel member list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMemberListResponse {
    pub members: Vec<ChannelMember>,
    pub next: NextCursor,
}

/// Channel member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMember {
    pub object: String,
    pub user: User,
    pub role: String,
}

/// Response for conversation endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationResponse {
    pub conversation: Conversation,
}

/// Conversation with cast and replies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub cast: CastWithReplies,
}

/// Cast with nested replies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CastWithReplies {
    #[serde(flatten)]
    pub cast: Cast,
    pub direct_replies: Vec<CastWithReplies>,
}

/// Response for single user lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub user: User,
}

/// Response for bulk user lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkUsersResponse {
    pub users: Vec<User>,
}

/// Response for single cast lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CastResponse {
    pub cast: Cast,
}

/// Response for bulk cast lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkCastsResponse {
    pub casts: Vec<Cast>,
}

/// Response for reactions on a cast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionsResponse {
    pub reactions: Vec<Reaction>,
    pub next: NextCursor,
}

/// A reaction object matching Farcaster v2 API schema.
/// The `cast` field contains the full hydrated Cast object per the Neynar
/// `ReactionWithCastInfo` schema. It is `None` when the target cast has
/// been deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    pub object: String,
    pub reaction_type: String,
    pub reaction_timestamp: String,
    pub user: User,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cast: Option<Cast>,
}

/// Response for channel listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsResponse {
    pub channels: Vec<Channel>,
    pub next: NextCursor,
}

/// Response for notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationsResponse {
    pub notifications: Vec<Notification>,
    pub next: NextCursor,
}

/// A notification object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub object: String,
    pub r#type: String,
    pub cast: Option<Cast>,
    pub user: User,
    pub timestamp: String,
}

/// Response for fname availability check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FnameAvailabilityResponse {
    pub available: bool,
}

/// Response for username proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameProofResponse {
    pub r#type: String,
    pub fid: u64,
    pub username: String,
    pub timestamp: u64,
    pub owner: String,
}

/// Response for user storage allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAllocationsResponse {
    pub total_active_units: u64,
    pub allocations: Vec<StorageAllocation>,
}

/// A single storage allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAllocation {
    pub object: String,
    pub units: u64,
    pub expiry: u64,
}

/// Response for user storage usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageUsageResponse {
    pub object: String,
    pub casts: StorageUsage,
    pub reactions: StorageUsage,
    pub links: StorageUsage,
    pub verifications: StorageUsage,
    pub user_data: StorageUsage,
}

/// Storage usage for a message type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageUsage {
    pub used: u64,
    pub capacity: u64,
}

/// Response for block/mute list endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockListResponse {
    pub users: Vec<User>,
    pub next: NextCursor,
}

/// Response for onchain signer query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerResponse {
    pub object: String,
    pub signer_uuid: String,
    pub public_key: String,
    pub fid: u64,
    pub status: String,
}

/// Response for onchain events query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnChainEventsResponse {
    pub events: Vec<OnChainEventEntry>,
    pub next: NextCursor,
}

/// An onchain event entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnChainEventEntry {
    pub object: String,
    pub fid: u64,
    pub event_type: String,
    pub block_number: u32,
    pub block_timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_type: Option<u32>,
}

/// Error response matching Farcaster format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_serialization() {
        let user = User::default();
        let json = serde_json::to_string(&user).unwrap();
        assert!(json.contains("\"object\":\"user\""));
        assert!(json.contains("\"registered_at\":\"\""));
        assert!(json.contains("\"auth_addresses\":[]"));
        assert!(json.contains("\"verified_accounts\":[]"));
    }

    #[test]
    fn test_cast_serialization() {
        let cast = Cast::default();
        let json = serde_json::to_string(&cast).unwrap();
        assert!(json.contains("\"object\":\"cast\""));
        assert!(json.contains("\"parent_author\""));
        assert!(json.contains("\"mentioned_profiles\":[]"));
        assert!(json.contains("\"type\":\"cast\""));
    }

    #[test]
    fn test_channel_serialization() {
        let channel = Channel::default();
        let json = serde_json::to_string(&channel).unwrap();
        assert!(json.contains("\"url\":\"\""));
        assert!(json.contains("\"created_at\":\"\""));
    }

    #[test]
    fn test_followers_response_serialization() {
        let response = FollowersResponse {
            users: vec![],
            next: NextCursor {
                cursor: Some("abc".to_string()),
            },
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"cursor\":\"abc\""));
    }

    #[test]
    fn test_reaction_serialization() {
        let reaction = Reaction {
            object: "likes".to_string(),
            reaction_type: "like".to_string(),
            reaction_timestamp: "2024-01-01T00:00:00.000Z".to_string(),
            user: User::default(),
            cast: None,
        };
        let json = serde_json::to_string(&reaction).unwrap();
        assert!(json.contains("\"reaction_timestamp\""));
        assert!(json.contains("\"object\":\"likes\""));
    }

    #[test]
    fn test_verified_addresses_has_primary() {
        let va = VerifiedAddresses::default();
        let json = serde_json::to_string(&va).unwrap();
        assert!(json.contains("\"primary\""));
    }
}
