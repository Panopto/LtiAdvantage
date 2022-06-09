using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using LtiAdvantage.AssignmentGradeServices;
using LtiAdvantage.DeepLinking;
using LtiAdvantage.NamesRoleProvisioningService;
using LtiAdvantage.Utilities;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using JsonClaimValueTypes = Microsoft.IdentityModel.JsonWebTokens.JsonClaimValueTypes;

namespace LtiAdvantage.Lti
{
    /// <inheritdoc />
    /// <summary>
    /// The base class for LtiResourceLinkRequest and LtiDeepLinkingRequest.
    /// </summary>
    public class LtiRequest : JwtPayload
    {
        private readonly JsonSerializerSettings serializerSettings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore,
            Formatting = Formatting.None
        };

        #region Constructors

        /// <inheritdoc />
        /// <summary>
        /// Create an empty instance.
        /// </summary>
        public LtiRequest()
        {
        }

        #endregion

        /// <summary>
        /// Override the base Claims property in order to process claims using Newtonsoft
        /// </summary>
        public override IEnumerable<Claim> Claims
        {
            get
            {
                List<Claim> claims = new List<Claim>();
                string issuer = this.Iss;
                foreach (KeyValuePair<string, object> kvp in this)
                {
                    string key = kvp.Key;
                    if (kvp.Value is string stringValue)
                    {
                        claims.Add(new Claim(kvp.Key, stringValue, ClaimValueTypes.String, issuer, issuer));
                    }
                    else if (kvp.Value is long longValue)
                    {
                        claims.Add(new Claim(kvp.Key, longValue.ToString(), ClaimValueTypes.Integer64, issuer, issuer));
                    }
                    else if (kvp.Value is JArray array)
                    {
                        string value = array.ToString(Formatting.None);
                        claims.Add(new Claim(key, value, JsonClaimValueTypes.JsonArray, issuer, issuer)
                        {
                            Properties = { [JwtSecurityTokenHandler.JsonClaimTypeProperty] = kvp.Value.GetType().ToString() }
                        });
                    }
                    else if (kvp.Value is JObject obj)
                    {
                        string value = obj.ToString(Formatting.None);
                        claims.Add(new Claim(key, value, JsonClaimValueTypes.Json, issuer, issuer)
                        {
                            Properties = { [JwtSecurityTokenHandler.JsonClaimTypeProperty] = kvp.Value.GetType().ToString() }
                        });
                    }
                }
                return claims;
            }
        }

        #region Required Message Claims

        // See https://www.imsglobal.org/spec/lti/v1p3/#required-message-claims
        // See https://openid.net/specs/openid-connect-core-1_0.html#Claims
        // See https://purl.imsglobal.org/spec/lti/v1p3/schema/json/Token.json

        /// <summary>
        /// REQUIRED. Audience(s) for whom this ID Token is intended i.e. the Tool.
        /// It MUST contain the OAuth 2.0 client_id of the Tool as an audience value.
        /// It MAY also contain identifiers for other audiences. In the general case,
        /// the aud value is an array of case-sensitive strings. In the common special
        /// case when there is one audience, the aud value MAY be a single case-sensitive string.
        /// </summary>
        public string[] Audiences
        {
            get { return this.GetClaimValue<string[]>(JwtRegisteredClaimNames.Aud); }
            set { this.SetClaimValue(JwtRegisteredClaimNames.Aud, value);}
        }

        /// <summary>
        /// The required https://purl.imsglobal.org/spec/lti/claim/deployment_id claim's value
        /// contains a string that identifies the platform-tool integration governing the message.
        /// </summary>
        public string DeploymentId
        {
            get { return this.GetClaimValue(Constants.LtiClaims.DeploymentId); }
            set { this.SetClaimValue(Constants.LtiClaims.DeploymentId, value); }
        }

        /// <summary>
        /// User ID as defined in LTI 1.1.
        /// </summary>
        public string Lti11LegacyUserId
        {
            get { return this.GetClaimValue(Constants.LtiClaims.Lti11LegacyUserId); }
            set { this.SetClaimValue(Constants.LtiClaims.Lti11LegacyUserId, value); }
        }

        /// <summary>
        /// The type of LTI message.
        /// </summary>
        public string MessageType
        {
            get { return this.GetClaimValue(Constants.LtiClaims.MessageType); }
            set { this.SetClaimValue(Constants.LtiClaims.MessageType, value); }
        }

        /// <summary>
        /// Value used to associate a Client session with an ID Token.
        /// Should only be used once. Use GenerateCryptoNonce to generate
        /// a cryptographic nonce value. Required.
        /// <example>
        /// LtiResourceLinkRequest request;
        /// request.Nonce = LtiResourceLinkRequest.GenerateCryptographicNonce();
        /// </example>
        /// </summary>
        public new string Nonce
        {
            get { return base.Nonce; }
            set { this.SetClaimValue(JwtRegisteredClaimNames.Nonce, value); }
        }

        /// <summary>
        /// An array of roles as defined in the Core LTI specification.
        /// </summary>
        public Role[] Roles
        {
            get { return this.GetClaimValue<Role[]>(Constants.LtiClaims.Roles); }
            set { this.SetClaimValue(Constants.LtiClaims.Roles, value); }
        }

        /// <summary>
        /// The tool's url.
        /// </summary>
        public string TargetLinkUri
        {
            get { return this.GetClaimValue(Constants.LtiClaims.TargetLinkUri); }
            set { this.SetClaimValue(Constants.LtiClaims.TargetLinkUri, value);}
        }

        /// <summary>
        /// The required 'sub' claim's value contains a string acting as an opaque identifier for
        /// the user that initiated the launch. This value MUST be immutable and MUST be unique
        /// within the platform instance.
        /// </summary>
        public string UserId
        {
            get { return this.GetClaimValue(JwtRegisteredClaimNames.Sub); }
            set { this.SetClaimValue(JwtRegisteredClaimNames.Sub, value); }
        }

        /// <summary>
        /// The version to which the message conforms. Must be "1.3.0".
        /// </summary>
        public string Version
        {
            get { return this.GetClaimValue(Constants.LtiClaims.Version); }
            set { this.SetClaimValue(Constants.LtiClaims.Version, value); }
        }

        #endregion

        #region Optional Message Claims

        /// <summary>
        /// Properties of the context from which the launch originated (for example, course id and title).
        /// </summary>
        public ContextClaimValueType Context
        {
            get { return this.GetClaimValue<ContextClaimValueType>(Constants.LtiClaims.Context); }
            set { this.SetClaimValue(Constants.LtiClaims.Context, value); }
        }

        /// <summary>
        /// This is a map of key/value custom parameters which are to be included with the launch.
        /// </summary>
        public Dictionary<string, string> Custom
        {
            get { return this.GetClaimValue<Dictionary<string, string>>(Constants.LtiClaims.Custom); }
            set { this.SetClaimValue(Constants.LtiClaims.Custom, value); }
        }

        /// <summary>
        /// This is a map of key/value extension parameters which are to be included with the launch.
        /// </summary>
        public Dictionary<string, string> Ext
        {
            get { return this.GetClaimValue<Dictionary<string, string>>(Constants.LtiClaims.Ext); }
            set { this.SetClaimValue(Constants.LtiClaims.Ext, value); }
        }

        /// <summary>
        /// Information to help the Tool present itself appropriately.
        /// </summary>
        public LaunchPresentationClaimValueType LaunchPresentation
        {
            get { return this.GetClaimValue<LaunchPresentationClaimValueType>(Constants.LtiClaims.LaunchPresentation); }
            set { this.SetClaimValue(Constants.LtiClaims.LaunchPresentation, value); }
        }

        /// <summary>
        /// Properties about available Learning Information Services (LIS),
        /// usually originating from the Student Information System.
        /// </summary>
        public LisClaimValueType Lis
        {
            get { return this.GetClaimValue<LisClaimValueType>(Constants.LtiClaims.Lis); }
            set { this.SetClaimValue(Constants.LtiClaims.Lis, value);}
        }

        /// <summary>
        /// Properties associated with the platform initiating the launch.
        /// </summary>
        public PlatformClaimValueType Platform
        {
            get { return this.GetClaimValue<PlatformClaimValueType>(Constants.LtiClaims.Platform); }
            set { this.SetClaimValue(Constants.LtiClaims.Platform, value); }
        }

        /// <summary>
        /// An array of the user_id ('sub' claim) values which the current user can access as a mentor.
        /// </summary>
        public string[] RoleScopeMentor
        {
            get { return this.GetClaimValue<string[]>(Constants.LtiClaims.RoleScopeMentor); }
            set { this.SetClaimValue(Constants.LtiClaims.RoleScopeMentor, value); }
        }

        #endregion

        #region Resource Link Request claims

        // See https://www.imsglobal.org/spec/lti/v1p3/#required-message-claims
        // See https://openid.net/specs/openid-connect-core-1_0.html#Claims
        // See https://purl.imsglobal.org/spec/lti/v1p3/schema/json/Token.json

        /// <summary>
        /// The Assignment and Grade Services claim.
        /// </summary>
        public AssignmentGradeServicesClaimValueType AssignmentGradeServices
        {
            get { return this.GetClaimValue<AssignmentGradeServicesClaimValueType>(Constants.LtiClaims.AssignmentGradeServices); }
            set { this.SetClaimValue(Constants.LtiClaims.AssignmentGradeServices, value); }
        }

        /// <summary>
        /// The Names and Roles Provisioning Service claim.
        /// </summary>
        public NamesRoleServiceClaimValueType NamesRoleService
        {
            get { return this.GetClaimValue<NamesRoleServiceClaimValueType>(Constants.LtiClaims.NamesRoleService); }
            set { this.SetClaimValue(Constants.LtiClaims.NamesRoleService, value); }
        }

        /// <summary>
        /// The required https://purl.imsglobal.org/spec/lti/claim/resource_link claim composes
        /// properties for the resource link from which the launch message occurs.
        /// <example>
        /// {
        ///   "id": "200d101f-2c14-434a-a0f3-57c2a42369fd",
        ///   ...
        /// }
        /// </example>
        /// </summary>
        public ResourceLinkClaimValueType ResourceLink
        {
            get { return this.GetClaimValue<ResourceLinkClaimValueType>(Constants.LtiClaims.ResourceLink); }
            set { this.SetClaimValue(Constants.LtiClaims.ResourceLink, value); }
        }

        #endregion

        #region Deep Linking Request claims

        /// <summary>
        /// Deep Linking settings.
        /// </summary>
        public DeepLinkingSettingsClaimValueType DeepLinkingSettings
        {
            get { return this.GetClaimValue<DeepLinkingSettingsClaimValueType>(Constants.LtiClaims.DeepLinkingSettings); }
            set { this.SetClaimValue(Constants.LtiClaims.DeepLinkingSettings, value); }
        }

        #endregion

        #region Deep Linking Response claims

        /// <summary>
        /// A possibly empty list of content items.
        /// </summary>
        public ContentItem[] ContentItems
        {
            get { return this.GetClaimValue<ContentItem[]>(Constants.LtiClaims.ContentItems); }
            set { this.SetClaimValue(Constants.LtiClaims.ContentItems, value); }
        }

        /// <summary>
        /// The value from deep linking settings.
        /// </summary>
        public string Data
        {
            get { return this.GetClaimValue(Constants.LtiClaims.Data); }
            set { this.SetClaimValue(Constants.LtiClaims.Data, value); }
        }

        /// <summary>
        /// Optional plain text message.
        /// </summary>
        public string ErrorLog
        {
            get { return this.GetClaimValue(Constants.LtiClaims.ErrorLog); }
            set { this.SetClaimValue(Constants.LtiClaims.ErrorLog, value); }
        }

        /// <summary>
        /// Optional plain text message.
        /// </summary>
        public string ErrorMessage
        {
            get { return this.GetClaimValue(Constants.LtiClaims.ErrorMessage); }
            set { this.SetClaimValue(Constants.LtiClaims.ErrorMessage, value); }
        }

        /// <summary>
        /// Optional plain text message.
        /// </summary>
        public string Log
        {
            get { return this.GetClaimValue(Constants.LtiClaims.Log); }
            set { this.SetClaimValue(Constants.LtiClaims.Log, value); }
        }

        /// <summary>
        /// Optional plain text message.
        /// </summary>
        public string Message
        {
            get { return this.GetClaimValue(Constants.LtiClaims.Message); }
            set { this.SetClaimValue(Constants.LtiClaims.Message, value); }
        }

        #endregion

        #region Optional OpenID Connect claims

        // See https://www.iana.org/assignments/jwt/jwt.xhtml#claims
        // See https://openid.net/specs/openid-connect-core-1_0.html#Claims
        // See https://purl.imsglobal.org/spec/lti/v1p3/schema/json/Token.json

        /// <summary>
        /// End-User's preferred e-mail address. Its value MUST conform to the RFC 5322 [RFC5322]
        /// addr-spec syntax. The Tool MUST NOT rely upon this value being unique.
        /// <example>
        /// "jane@example.org"
        /// </example>
        /// </summary>
        public string Email
        {
            get { return this.GetClaimValue(JwtRegisteredClaimNames.Email); }
            set { this.SetClaimValue(JwtRegisteredClaimNames.Email, value); }
        }

        /// <summary>
        /// Surname(s) or last name(s) of the End-User. Note that in some cultures, people can have
        /// multiple family names or no family name; all can be present, with the names being separated
        /// by space characters.
        /// <example>
        /// "Doe"
        /// </example>
        /// </summary>
        public string FamilyName
        {
            get { return this.GetClaimValue(JwtRegisteredClaimNames.FamilyName); }
            set { this.SetClaimValue(JwtRegisteredClaimNames.FamilyName, value);}
        }

        /// <summary>
        /// Given name(s) or first name(s) of the End-User. Note that in some cultures, people can have
        /// multiple given names; all can be present, with the names being separated by space characters.
        /// <example>
        /// "Jane"
        /// </example>
        /// </summary>
        public string GivenName
        {
            get { return this.GetClaimValue(JwtRegisteredClaimNames.GivenName); }
            set { this.SetClaimValue(JwtRegisteredClaimNames.GivenName, value);}
        }

        /// <summary>
        /// Middle name(s) of the End-User. Note that in some cultures, people can have multiple middle
        /// names; all can be present, with the names being separated by space characters. Also note that
        /// in some cultures, middle names are not used.
        /// <example>
        /// "Marie"
        /// </example>
        /// </summary>
        public string MiddleName
        {
            get { return this.GetClaimValue(Constants.OidcClaims.MiddleName); }
            set { this.SetClaimValue(Constants.OidcClaims.MiddleName, value);}
        }

        /// <summary>
        /// End-User's full name in displayable form including all name parts, possibly including titles and
        /// suffixes, ordered according to the End-User's locale and preferences.
        /// <example>
        /// "Ms. Jane Marie Doe"
        /// </example>
        /// </summary>
        public string Name
        {
            get { return this.GetClaimValue(Constants.OidcClaims.Name); }
            set { this.SetClaimValue(Constants.OidcClaims.Name, value);}
        }

        /// <summary>
        /// URL of the End-User's profile picture. This URL MUST refer to an image file (for example, a PNG,
        /// JPEG, or GIF image file), rather than to a Web page containing an image. Note that this URL SHOULD
        /// specifically reference a profile photo of the End-User suitable for displaying when describing the
        /// End-User, rather than an arbitrary photo taken by the End-User.
        /// <example>
        /// "http://example.org/jane.jpg"
        /// </example>
        /// </summary>
        public string Picture
        {
            get { return this.GetClaimValue(Constants.OidcClaims.Picture); }
            set { this.SetClaimValue(Constants.OidcClaims.Picture, value);}
        }

        #endregion

        /// <summary>
        /// Override the base serialization in order to use Newtonsoft
        /// </summary>
        /// <returns></returns>
        public override string SerializeToJson()
        {
            return JsonConvert.SerializeObject(this, serializerSettings);
        }
    }
}
