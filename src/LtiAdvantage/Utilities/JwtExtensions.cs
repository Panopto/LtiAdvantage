using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.IdentityModel.Tokens;

namespace LtiAdvantage.Utilities
{
    /// <summary>
    /// Extensions to make working with JWT Tokens easier.
    /// </summary>
    public static class JwtExtensions
    {
        /// <summary>
        /// Get the payload claim value as a string.
        /// </summary>
        /// <returns>The claim value as a string.</returns>
        public static string GetClaimValue(this JwtPayload payload, string type)
        {
            return GetClaimValue<string>(payload, type);
        }

        /// <summary>
        /// Get the payload claim value as an object of type T.
        /// </summary>
        /// <typeparam name="T">The expected Type of the claim value.</typeparam>
        /// <param name="payload">The <see cref="JwtPayload"/> with the claim.</param>
        /// <param name="type">The claim type.</param>
        /// <returns>The claim value as an object of type T.</returns>
        public static T GetClaimValue<T>(this JwtPayload payload, string type)
        {
            if (payload.TryGetValue(type, out var value))
            {
                if (typeof(T).IsArray)
                {
                    if (value is string)
                    {
                        return JsonConvert.DeserializeObject<T>($"[\"{value}\"]");
                    }
                    else if (value is JArray)
                    {
                        return JsonConvert.DeserializeObject<T>(value.ToString());
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
                else if (typeof(T) == typeof(string))
                {
                    return JsonConvert.DeserializeObject<T>($"\"{value}\"");
                }
                else
                {
                    return JsonConvert.DeserializeObject<T>(value.ToString());
                }
            }

            return default(T);
        }

        /// <summary>
        /// Set payload claim value as an object of type T
        /// 
        /// Extra logic is present to differentiate between strings, ints, arrays, and objects
        /// </summary>
        /// <typeparam name="T">The expected Type of the claim value.</typeparam>
        /// <param name="payload">The <see cref="JwtPayload"/> with the claim.</param>
        /// <param name="type">The claim type.</param>
        /// <param name="value"> The claim value </param>
        public static void SetClaimValue<T>(this JwtPayload payload, string type, T value)
        {
            if (payload.ContainsKey(type))
            {
                payload.Remove(type);
            }

            // Serialize our incoming value to JSON and subsequently deserialize to object so we end up w/ appropriate JToken value in dictionary
            payload.Add(type, JsonConvert.DeserializeObject(JsonConvert.SerializeObject(value)));
        }
    }
}
