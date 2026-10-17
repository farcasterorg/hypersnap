mod tests {
    use rand::Rng;
    use serde::Deserialize;

    use crate::{
        core::validations,
        proto::{cast_add_body, embed, Embed},
        version::version::EngineVersion,
    };

    #[derive(Deserialize)]
    struct Message {
        data: MessageData,
    }

    #[derive(Deserialize)]
    struct MessageData {
        #[serde(rename = "castAddBody")]
        cast_add_body: Option<CastAddBody>,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum EmbedUrlOrCastId {
        Url(EmbedUrl),
        CastId(EmbedCastId),
    }

    #[derive(Deserialize)]
    struct EmbedUrl {
        url: String,
    }

    #[derive(Deserialize)]
    struct EmbedCastId {
        #[serde(rename = "castId")]
        cast_id: CastId,
    }

    #[derive(Deserialize)]
    struct CastAddBody {
        #[serde(rename = "embedsDeprecated")]
        embeds_deprecated: Vec<String>,
        mentions: Vec<u64>,
        #[serde(rename = "parentCastId")]
        parent_cast_id: Option<CastId>,
        text: String,
        embeds: Vec<EmbedUrlOrCastId>,
        #[serde(rename = "mentionsPositions")]
        mentions_positions: Vec<u64>,
        #[serde(rename = "type")]
        cast_type: String,
    }

    #[derive(Deserialize)]
    struct CastId {
        fid: u64,
        hash: String,
    }

    #[derive(Deserialize)]
    struct PagedResponse {
        messages: Vec<Message>,
    }

    #[tokio::test]
    async fn test_cast_validation() {
        let n: u32 = rand::thread_rng().gen::<u32>() % 10000;
        let resp = reqwest::get(format!(
            "https://snap.farcaster.xyz:3381/v1/castsByFid?fid={}",
            n
        ))
        .await;
        assert!(!resp.is_err());

        let response = resp.unwrap();
        let resp_json = response.text().await.unwrap();

        let json = serde_json::from_str::<PagedResponse>(&resp_json);
        let page = json.unwrap();
        for msg in page.messages {
            match msg.data.cast_add_body {
                Some(body) => {
                    let cast = crate::proto::CastAddBody {
                        embeds_deprecated: body.embeds_deprecated,
                        mentions: body.mentions,
                        embeds: body
                            .embeds
                            .into_iter()
                            .map(|e| match e {
                                EmbedUrlOrCastId::Url(url) => Embed {
                                    embed: Some(embed::Embed::Url(url.url)),
                                },
                                EmbedUrlOrCastId::CastId(cast_id) => Embed {
                                    embed: Some(embed::Embed::CastId(crate::proto::CastId {
                                        fid: cast_id.cast_id.fid,
                                        hash: hex::decode(&cast_id.cast_id.hash[2..]).unwrap(),
                                    })),
                                },
                            })
                            .collect(),
                        text: body.text,
                        mentions_positions: body
                            .mentions_positions
                            .iter()
                            .map(|p| *p as u32)
                            .collect(),
                        r#type: match body.cast_type.as_str() {
                            "CAST" => 0,
                            "LONG_CAST" => 1,
                            "TEN_K_CAST" => 2,
                            _ => 1,
                        },
                        parent: body.parent_cast_id.map(|p| {
                            cast_add_body::Parent::ParentCastId(crate::proto::CastId {
                                fid: p.fid,
                                hash: hex::decode(p.hash.replace("0x", "")).unwrap(),
                            })
                        }),
                    };
                    assert!(
                        // Assume pro user is true to avoid failures on casts with 10k characters or 4 embeds.
                        validations::cast::validate_cast_add_body(
                            &cast,
                            true,
                            true,
                            EngineVersion::latest()
                        )
                        .is_ok(),
                        "Failed to validate cast {:?}",
                        serde_json::to_string(&cast)
                    );
                }
                None => {}
            }
        }
    }

    fn cast_with_embeds(count: usize) -> crate::proto::CastAddBody {
        // Fully qualified: this module already defines its own `CastAddBody`
        // deserialization fixture, so importing the proto type would shadow it.
        crate::proto::CastAddBody {
            embeds: (0..count)
                .map(|i| Embed {
                    embed: Some(embed::Embed::Url(format!("https://example.com/{}", i))),
                })
                .collect(),
            ..Default::default()
        }
    }

    fn validate_embeds(
        count: usize,
        is_pro_user: bool,
        version: EngineVersion,
    ) -> Result<(), validations::error::ValidationError> {
        validations::cast::validate_cast_add_body(
            &cast_with_embeds(count),
            false,
            is_pro_user,
            version,
        )
    }

    /// Pins both sides of the `IncreaseEmbedLimitForAllUsers` boundary. The pre-V20 row is what
    /// makes replay of existing history safe: a non-Pro cast with 3 embeds was invalid when it
    /// would have been signed, and must stay invalid forever at that version. The post-V20 row
    /// is what keeps this node in consensus with mainnet, which has merged 4-embed non-Pro casts
    /// since 2026-08-13.
    #[test]
    fn embed_limit_is_four_for_everyone_from_v20() {
        use validations::error::ValidationError;

        // Below the boundary: Pro gets 4, everyone else gets 2.
        assert!(validate_embeds(2, false, EngineVersion::V19).is_ok());
        assert!(matches!(
            validate_embeds(3, false, EngineVersion::V19),
            Err(ValidationError::EmbedsExceedsLimit)
        ));
        assert!(validate_embeds(4, true, EngineVersion::V19).is_ok());
        assert!(matches!(
            validate_embeds(5, true, EngineVersion::V19),
            Err(ValidationError::EmbedsExceedsLimit)
        ));

        // At and above the boundary: 4 for everyone, Pro or not.
        for is_pro_user in [false, true] {
            assert!(validate_embeds(4, is_pro_user, EngineVersion::V20).is_ok());
            assert!(matches!(
                validate_embeds(5, is_pro_user, EngineVersion::V20),
                Err(ValidationError::EmbedsExceedsLimit)
            ));
            assert!(validate_embeds(4, is_pro_user, EngineVersion::latest()).is_ok());
        }
    }
}
