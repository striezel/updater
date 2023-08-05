/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/116.0.1/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "30c189144da2e17dba31115a5ff6705c616876cc416df9508733696b81826d7c9627803d34c7a7c3c0620c1a512e566021d3dbeaf0ad438542aee170992be5d8" },
                { "af", "1c5ea3ff25599193257c615fc30a8c143430595eed7542f88493d5b448d2dfacce82281f08531c3292571b6560372c163978564ac4f8d8ac1ddc5e4766a473e6" },
                { "an", "4112f4379512ca8d6372909aa9cf6f20cfb8d8cf044676ffc3d8f2dabecc189792ea0e88e8cce3f7ec91a5ec865af76a7d334566b8859f8e556950c86b8b89c5" },
                { "ar", "9927b014789332549ddd88e667cb0a05d1f238bc5ac1017d7aa3d09ce1ee2f92f368f2abc1f33c9a5834ced91b1f5f8affb8870b95aca6a8bca72e3fa1a22eb9" },
                { "ast", "371aa5d8a57eab546681a078864dd45ab326f015e71bcd6d504ba4f5eba01d4f812052cec589a0bf4136bf1d0339a5faf7ee605b943dfe1e9f39cf3d9cf63d1d" },
                { "az", "82c3f22588a078f640936b6322e889065a21cdf11f803fa4d964f31b09b5bd75462d0ced7fd3ff85d41f9b7303dbc549a80ea09b6bd847c008a6b68ab050caf6" },
                { "be", "737ca140b6a39c3d318157a283e7c82ff8e9d4838ecf2285b6e13a3b2face65931317367965be6935886da77a1bdd35c01abc933c8904a37e031b4e73162a8fd" },
                { "bg", "6409a36e10db4f13538d725adf6f4cc2efd9bbde4ac84d776d5fd7e8a41745b24e3c524b6c7b5749d8d5d18793bc1d50370819a870b8d6245dcd68a6db81e70f" },
                { "bn", "cc6825efddc70ba07823044732e572fa516fcd6a70eeb32d5efabb79512151eb7f56b6054b8999941b0836686e8c7e2674019ebd7aa1413665a955b6242db248" },
                { "br", "158861b5f2d1cc5fc01be6abfff81f7799c9c0ea5f398d5f3989eba4d6e4190d221992947402b6d83b7b94f16e157269e996478ddf130c5229f7a430c1f1b705" },
                { "bs", "a17b02408e339819fead2b451b2dc5a6ee7470f14d0630659c8999be4438bb118521b2a3560466effe3a36e3f02d7fb44c04be03c0d75287018406cf70eec9a6" },
                { "ca", "7480394db9e566cc11eac49fa1d9754e628dcdb67f88170fd59fe04d37185d19e95bb9925efc6f45c63fc86b7913ad6ca0f5752b4e06334bb311c59bf11b5623" },
                { "cak", "829721fa99631a043d11639f4b5477310f410c014e15b10bce284aabb5cf697d51d4364f60ddd4878477ee51bd94aa559f7e3c5216ceb1fac9207a03087d948f" },
                { "cs", "408499bf9e5ba15e5a753e3c019b7ad2444c93535fd6aa399baccfdf416f9b45cb2b5e319b8fd22f6ba0f3a5851250b0abc2e7f03e1bd6476896758ebc772064" },
                { "cy", "a09ed19d5d05f8b46be14b2f0cd562917e99744c90275b35deef9785b0fe62e494dbccf91d6d73c21e04781dd522103b0e594cab7cfcb2261887d8e2c5a40d0b" },
                { "da", "93cb00766933ac09222b4bd7d8d5f6d93a64775a7df0a18ae0b921a8062654af19d56576c9cfe5af9066b86fbdd0acb6ae644b501c6d28753d67dae5b6059e86" },
                { "de", "b2a660af3b6fa32e2446cc08e8d07205e9dacfbe5c98f17e89ffaa9b5f90575593ba0b2680cb3717c336d630256329120f135873af7b45db01e2c990850ec5aa" },
                { "dsb", "cb61b9214efdce542047068690bd4938c5dbffb4124a7dede0226aee3174e5a2e1b374685953eace05dcc116c390f9c4d807d3a88a1253288793d2d096f6ced9" },
                { "el", "e61cf0322daa2510372ce5489d49af57abb4d2fa9cc3ed5d1e779d1e41868adfd4d77e464ba74ac908a85b2c0369713cc8d7e4f206ea93c70fc68540430ffe64" },
                { "en-CA", "775de8252c2b7f635bd6f80a014834e9b5745fd0ab9bedb08d459cbcbcc0ffdcb3b73aaced49d5259e962eeaa84f47a32ca0939b0c092d1525286eee357f5fef" },
                { "en-GB", "47737430581394f2b3428132250263fd7665215a14c922d9c2832bcba73a364806864d7eb8eb1440450b996ee910334f655a5900bc905443cd9445f4edc6dfe9" },
                { "en-US", "3da176619226bc9acff9466be53d21bbb20a0b8f3abe2fb53c6121201bab3fe58e86e4f6ff6dfd95eab28625f75f88c90f319bbcfbb914f2b15d250ef21ffcd6" },
                { "eo", "561b901d8ca9c7e65e065d3a7d0166ef712b5e27a17a1e2b14a0a83293ff016c66fd6a1c3a20edef745b1b44090e049c434b4703424a66362abd4ed5af05e241" },
                { "es-AR", "1b456527cd75829b3a38f8a41bf40ce3683746fe2a4d559f5eb9754f9469b240a555ef1543e219f31a087f44a290db602b2a04ae12a89772d584fb6185024464" },
                { "es-CL", "ef27eb5f951d3472df68e7e1b7d1b5519bc6240ce89feead089317366008d2690fcdb35aedc56eacd82c6d4c4b4dae13547e2bdb67af3d137e155b569fbeb0ce" },
                { "es-ES", "c75143a3cf199466e520ae2df2a7e3831fd0e14ba561c7343afd0278ce3fd222e13eb4d482b0a2b061a50770758c19494bacff4d53180c5797a1930680759cc1" },
                { "es-MX", "4ccf7ebaa11fee5bad18592db90bfcf2a30343d3c95cb17a287a9545f5e4b7416648fa03cf8000a7fbfdee8f98123a6a0d961241c6a5e11c2257c557562d1619" },
                { "et", "86e972cc4126ce4a994e47ed1e9a6f66a1350acc3dacb00341dc20fed9942a41b33babe5c0c3e8e5bbaeffe47ab8d1f85dd9ea352e7f4c61424ee112cc22709c" },
                { "eu", "2825e9a53672747cc56ddce3c3d40dc6a469f7cf007b1164830270447c8ae424af5faf421a3f25543f020ebd14d3d746ababbbe25cfeba103a8a39ecc54d1e6c" },
                { "fa", "1a09800be408815b2097539a78396c23798d193a5ac28d42fdfc5556b40513e0877eb3a6bea8b193739fefc5ccacbe17b58da7552ad3cd57338f831279dac627" },
                { "ff", "705b286c70dd2b26f7439eb268a83eb363a5cbc558f3c699cae13d0b9b8de8ef1504aa72a42892e32d0992368e62e53ce476d17bb8d50f09938c50ee294065cc" },
                { "fi", "68766c4acee67b4e72314ff14d45cfdfcaa5a1bc821d3d496e8ed33de95a8a5ea0b5efe790e5eaa817c83b2a9c3a248c04948612c3729544f710363f996143ab" },
                { "fr", "a00ccd74751ee074014685efb67a2bf1774f5f8bb29bc9ab18efa5257c929882eab09db6cd2180ba0dbe12c7ce524a213597db65c3b184e167af6623f422bdbd" },
                { "fur", "25a5622d2db39681825164c06512f1885393564f640796e137aff8a10d6f97c875d890ba4876efde2c9d27e4b5b51c10a5a7cc1817ca729fbc6ba261533fa9fd" },
                { "fy-NL", "699ba5854f802c0d0c71e2736fc9098ec7fd7c4a59652591373b607cc8fa05732fde71e9cd823372de5162d71b7faecdcb27dc57b4a04584a4d24788d2952dda" },
                { "ga-IE", "0f0f73b2953122881378b2c5618d1dc3701a2f33234d6e38591ea3fbcc3ea89193e0878607e8862f06ee7307ff5607b51b95c0deff343978a99a92ebcc6e252c" },
                { "gd", "819d4cb1e33bb602895e4e8eb207314fb168a29769dbcb1b5c09f3f16bfc294947a3aa164aaa78c8748d0013452f9d3abb2021312afe2243a3f897d59c6dddbc" },
                { "gl", "0ac3d5e070b2c31b606244ef18ae0e56ddd55c6ace29771f4eea129db295b4b9321e9cf2e07fcd897052905fabf27bf580fbbe6dfda8105ded3516537d47a27a" },
                { "gn", "508454baf4f5b9c57f429d75db3e86c57d5e5bc0e1cd095f34e1e33195385787962a8deaf679db2821916dcc693c1534500d3b58c5e70ec7277e961ccd0811de" },
                { "gu-IN", "f3875f6bbe9e1e415056e4f2512ee90b24d1aec8b7bd4f9fed41d230933100dfa393119f2c3a9eb4a9ec391ad5e428ba4c1bbfb6957c6825f8661ffca25e7f5d" },
                { "he", "f6d12ef5c9ee62af3bfef5753f63e83c6d1ace3adadf0ca3a282c6ab99582a71de73bdd633f48389aebb28d15901bb704379c330a54a428021ce631b78098118" },
                { "hi-IN", "25deb855a062b6e439cdd30148f96ef1e86096a7b5a958c8a83ac806855de040a97be613d9cd9a6b0e599bcfd92880b13044ac0c98f9958d331c8d0ddcca35aa" },
                { "hr", "0c16c7bb52e5c41a3fbc81ff104967146317b983002e62057413a7cc3ad1c2587d462673a19214a24512c590cf3f42d1605ca7800d252218fec2a72e0ddc0540" },
                { "hsb", "b323f7684bb5d05fae69594ceff1cdac0a3e68c8f4ebff437cfa725f0293d773631c3fa56b37685f851f73332fb0fa3dbc17a2b5456901edc61bed676fc93475" },
                { "hu", "a9958a301484588ef39fee3fffb1c1f78a50e6fb996a20ff1fb7d647631aeebfa52739fc4482a015f293a698299e5956b0d4f70383819f2f276462530450ab3b" },
                { "hy-AM", "c6ca92d94b038d2cf658a7aa8e44ef3e902baeb10b582deb0ab8023d5f7462e32e755a9ec152b09e0345f3bfcbce7315ff47134ddfcd4ffbdf645118b363baed" },
                { "ia", "809a29907aad61d84d099511788d68185218971151e6935d6f6658b00f2adf6cb621e8637f7424cb30ad5f34619503e581b9cb0f6586855def04ad9e80c563a6" },
                { "id", "71201eccfc6b4f64d4beb1d6e5c41c36f5bdcbbb05e835da7ce1e81e8a30cc0a40aa530651a7b4e4eeedf3a31c0c1818a5fb0a46d4e8225bd50f8824facc1620" },
                { "is", "258fbd2d2fb3672e8b3cd44db6caca274452b8f63b9f02d7cd1e45284722b1134d1bdad7e81ff81149572c7809752c515a50b138dde208cf04e2dea275bba803" },
                { "it", "e18054302be9864198f64df9c1f4bcbae17d55fdd11982de72ffefa00b8e99be4a91cbe5a494647c7747a410d16b970ed335ff443af8dac23d7f4091f3e98067" },
                { "ja", "ca985a8938222497bead36592bd0ad4842fe9974f10412684670c9e0232976dc41c0278685a74baac6617aa0d26f5037d0f86a6ea00a36701c2cf39a3456071b" },
                { "ka", "06e54e91da52bc1771a3d73d016f192be5c577b9c3dd449cd6f4c72999f1166aa5416caa9837a3a61a3289d7d6c78d78115ee23a21d99980ba0028b801668bf6" },
                { "kab", "4aff69df5d31b3012afbc7f0ee4b1b936721e6c8fca63335d78f0aa31a12bb15ac28db56c2368f6cf8203a3be6e928e25a2a8652033e327bfb211c70c68cc51f" },
                { "kk", "5f5ca13cc8d2acc85c671bdde5cd9c5d94f40ea3f3b188dd09845ecd461c00a2812c09af5155ee2a5ce5fdad6c5fc5aff905faf3b96bacdfb2cb767f868ab4eb" },
                { "km", "4318c38822cb25fb8f290e5a06a1423bc862a788225936ae63188e60692e89557137c6584aac98aac6b6de465b1e30f206cbb692cb59235e763515367c5d53a4" },
                { "kn", "a520123008d9e18bd5caf6319b09a926eb2140399bb6214b3e362d418ebe1b24d36a026a0c7a51972a70a808485bbd54f134da12ea651797d0b7dfb469562828" },
                { "ko", "54343f14b0714a13ecc47f3329c77e07b48fb625c8ba1a659ab0bc549327f55e814fe9b9a7fb8e6dff9752e9b4ea9e6ed6dff85ef454fcbdf2c278ca6417e3f7" },
                { "lij", "34a254bd1316fbfd7560f09d5cc84ce32c8c65357d67ed25da3cf762520af62e2872a3486b51f40d178ae867108a80d8c14f8e89f3ed859b1ba046b020ecfb39" },
                { "lt", "999a83be72f8a3fa249be016f350fb1cccbf4f8c666f8b0b46b1fe239850a03c22849e535eeda99e968e29b5a59334c273ba64d3926d49c93723e44d1de39eed" },
                { "lv", "375dbf55ddf7474592e4a2f4375cf789c631d8475fce64620c91e6e0f50bf93ba17c2d866c0a69561bbe478bd8079a64218df9320ff3f8c6c6e97745d40268d0" },
                { "mk", "8592b35c5418868020d7694c22b33e37a268add76e09c034c8b73a8cf84907c7053d14dd20e712e42042911f0db71fe95282480cb85cdfcdbcaee6b1a9131746" },
                { "mr", "4248d8f93aae500a41fff0b32a2da479c4b42b3e310390de22d11c563a7dc3661a3cbd72bc6fc39a6dc9c7208b4dd55590caf8bae2cdcccfdb0c29e040694d0e" },
                { "ms", "a54c710f75292f68d24601101f8afdba9b2385f171723f3710564cde02cd88babdfd10830904ef95b95acc4456d0cc71321eef72eace95f6228824f3e8f0da72" },
                { "my", "e2583cfa05addee3915aa1938b255a4ef55cd259f62a2d61ae18401222034877548eafd775015c651d98a99518539619a8f53e16bf0b46bdb8840d849e292a07" },
                { "nb-NO", "32d6a7c8d19aaeeb331711c9e0b9cea2b38b44471fcdd6d332949afeb884123728f6f0d4e78ac52e8a9290894a1186b29dfdd9c1140465df3fbc6895ab064bad" },
                { "ne-NP", "30371bfb1641e64fdd97fcb79193a66ba0d723a2133f5cc164177aba21d9a55a0bb0f4cfe93c04fae193b65a124efe118698f2818869be72bd284f785604dfdc" },
                { "nl", "3c4d9d014409cc3d4ec2a3fcef64043773af3f14449e581bcae8ce145220304c95782520b09829c3e58c33f3a8f3e09a20c5f6fd9327ff81a79ec89e4085f85a" },
                { "nn-NO", "87009a407b26e5f70b7d0fb0deb839328ea5d70a460843a1c1c9090250507c67013262bc10c5b10b017ea42a0632b7f233f1585eaba0bb42fb75221599b3ebe7" },
                { "oc", "f5a6e33996f83fe486549741f10002b9ce0207a851f6cb58156a96774846b549b1406be05980603de26529c7ff0c3e18b0b8e4083ab9f39413c2e368f71e162f" },
                { "pa-IN", "d484b6649f3e8f067a5532e4487a2a15f2602f4f11e8d48d213670077a96e34ac8ffdeb788e562926259af09f5adeb21095099ce4320bd33d46c580cbf47b632" },
                { "pl", "45185da223849f13f4478b26c3d8c57fa9ac816304a7d8293aa7b203b9682e739a376c7788ca1e07671f9625c7442790f692122b65c67c8c17b94f6eedb519b6" },
                { "pt-BR", "5bd80714781bcab87bfd996002e12ef1d19a7be03fbe84e4699898233c7096ce1d48be7605947aab47ce79359c7f52d6d15cfa4288b47513fff0098f0001e924" },
                { "pt-PT", "e772e2cec269a27dba83ae58b3ce97f74da7a7df3a1a1aadbde876e89137d877500a1ef1a84ad3a3404eecb2f2f11668e20bf7f45f1ab2aa9580aad8c3057025" },
                { "rm", "c6cc72dbf0cc08e9740a80534e2d467ff0eaa7636ae5d10515b5f2c3cbf86a418a6def106e4718e63b8890ed4b3ca2910e5554f738e78815d80f988b6c7961bc" },
                { "ro", "18d1dc4e0fe0062322d47730e44abc3b1c230988c55d3824ac55d21906dc920ee877dabdf7df0632ca778aa7616f4e0601b481cddf38cd703b3436bae46e77af" },
                { "ru", "bb64477fc7c6a1c80a38e190a6bdf4e8bad3ef9c8db0afabdd8a3ddda88edc4e0e4d1f015c75238009e941f20c7f82829d06e7e3821cb47beb4334b5a913d12a" },
                { "sc", "bfdee322ebfbb1c97674333df8f79c1ceabed931b4211fe56df225fe2bd5f0bab2f2612f90f253f332f4a6f487125aa788309543afc2533255ab4b1feb0108b3" },
                { "sco", "5d7e6af0ceb4daa25ab654be9d3784c05bece3180e79e550383ac8053ad269b645ee3811366024e03021f8cb3d2b382476c661d29066a2545b2fe308900219f1" },
                { "si", "ad926f234c6bb5f9efa37f89f8b07a59257855ba158be546939ab525b0324ff0ef7ffa3affa2ed1b5cde58cfcc4ea02cc67372d0152d72a597fe0e2a18f44d5f" },
                { "sk", "1631b3d6ec1e3637e07fcc3ee7cd4fd8b16a6d4cccb002d1529e2187b0bd52b7e038733c39d909538e468e38ac39e20034e4c5d198aca53ca1d02d8ad794ee16" },
                { "sl", "036b5bea20a4f91ce6d4ab64df72a472708cd9fb843cc2e452ea6653b71a382abbddafa226ed436b271c3fa788d960a7fc860a5176c34a309ccbccbf055f19a4" },
                { "son", "f83c1ec8b768079b614b934cb557d1dea70a4dc3a4236b45d840cd4dde6a1a0462cbc5ac5a69eab1e80e138488d9e215e391251befc1bc5d31a186d6918fd78e" },
                { "sq", "79de991e9f80132b8acbc7eaba325cc7521df9744d3dce0a5ba001d3871ff2fb0391cc53139dfe05848765b5052a6f8388c28917dbd7d6993f89fe15a382cd35" },
                { "sr", "937e86352f66eb13cb2d2a8c20b17985bc08d2adf19e030c368b08f7f07bad9ef4179622a95d062b7b5af8da3398bc25925da5c3aa73e484eb9721cd69545291" },
                { "sv-SE", "adb93ffe1f5e2c16f622bb9921e6b78b5d64896769275d62b92543e91222bfa966e431875f73191f7c775317455cff297348e086352cd6d7622cb00108bf7828" },
                { "szl", "7941517d827cc9e3a8c97925b18ff68b5545bd0a70080beb65c87eb40dbfe1c86cbc327dd20a3758850b8667ff1b5a0a4ca8157f60e62f0f1e406e31cd06112f" },
                { "ta", "f5f4000eb7554b69a386e766ca458b1914a0350b707b59bc22c3ec82aafb16a8aeeaccb79a0b7b1ab292b7d9bff4352d14e2b7b0bd63cac7a3d502946dfe8743" },
                { "te", "55e3fabad67a5ffd6129d929eadd11724ed8fe310f23b73674da08dd19d76650bc67fa56b1547a34455d3109b482f7e446eccdc3a7815bedb1cf22b1dde265ac" },
                { "tg", "8aa3827c0c77e70e008f9c66214e68ef03fb2f322bafc69ec8e067fcd0fd2a0cfa02e20edfb8d8630347fd8c669ae35005c11ba022b915edb9efb2d3eab529b7" },
                { "th", "6762d6c6be0a61d4e16bdcaed76eeace531d337e8c23f286330f2f1904e23cf75430194706bd63da13eeb0a9edd1892bbdd309e0146841a09d392afb31b3d3f4" },
                { "tl", "fc71ddae4d9e2893c3cb4c8e4b1e16d8bca2e8f041be20158a7d353d0a70d2127a7ed11472c4f314c94b22693a18cd793ba4afcad7109386c78cfe0db2ced0da" },
                { "tr", "1e0e07a2edc1969be02d495873fe516c273378d870c2ed01477c34df52b9e2a8762d2b8c9f7a6cab19c488441e78f9a3de724a1d5b0e844977ced50ba03b8b4a" },
                { "trs", "851f116f8cc3a7a76918bc1300035922d1e4bb8a7a012d565a6292485afbc54f4137f5776781d4297a9f774e55eca5eefabd468c7845ada6f3ed69fa5f5b0f1a" },
                { "uk", "36d9ef47b529b859ee960bb783f2dd600f5240a1dfad5686c8d0ec8c512c87ab92abe7142271459364d9dbe0293cf3b392205351fb8c36da1a70dce46c559507" },
                { "ur", "c5caa86968569d582f41d6679dfa717c8338eb13eee4d7556277e4c8ffcbd0e34add605e7955ecde7f80794ebce75ab8bb655527e5878fa6a8f6c04837ea9c64" },
                { "uz", "97b0dad87eb044d49c3f1f1ded9b376831fe5012724c3fee5ec11285bbb1e7f09f69857683860140295569fe5d56a5bcb916a77a676af1014cab9bb51797df26" },
                { "vi", "a04c3f64b4c9808dbf4753ccc64c2536218b5086ad9a3a4cee1146b82b1d87bdba250430f64dada4370ef34b4db676ecb6e99fb3e1719ac82b2f68410d7fbaf5" },
                { "xh", "ec91996d1bfa2cb80c8a81c1fa53a514efb52460a64523d57973c75ec1f7672b0239e8e046f7fcdffc8ea7b3370e97654fb2d24d8e4f0926d71c14a0686fe5d8" },
                { "zh-CN", "d0ac26e0223bf3ffd843243e32bed48c3cd474deb13639a3afeb96ccdc3d923abeeebe8c56205acb646c51c5f3b02968bf9aa57b0809a645408bb17a82155521" },
                { "zh-TW", "422497fc69c00b7e4743a2355d11c2f32f2d6be6a5e2f1fb069249e86421ec7ed8c0104f08449c84daffce85e8c18622e504a928e399d6a27d69deafd01932fe" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/116.0.1/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "acc251c80c0ab52285f78616495a8fe3e01ffd9965febfc7a2a6643c0eab3c0f4a651c75bc2166c58c0c9c7cff01d135863200c9f7d1bda8b01beb26d798841d" },
                { "af", "762483509b7ba779eff3afedef121f9d282604e7b7943172648f857ec3490e8caa6f7a5726aee784ae5e00c6a5c7971f7fa4a53b42cd31076c01836856e1c410" },
                { "an", "c9febcd5d9cd561f0ce301e490d290659fd9adc77b8a162da8b08d9309dbba437079c19b842fc327d3f3733b27af89ef86ba0669b12d6edf697e9add679bb90f" },
                { "ar", "7322d14e9f604798d53141c919d9f2622ac247898c871791a3c5f432d25455ac5142c4b12d2d7e0fd99e0e80592ff9a9bba4dce18c54dc423b8e5dca86e458a9" },
                { "ast", "2fbf59334c5c2c650d8111d73bd958b5e3982169dec81ed2458b9bc844f1c774231cb2e0a4d34a7c672584ee715b5af51cfc418a596159f0d8004b26970385c6" },
                { "az", "9191af9e86ff8653e2c1f3862b767f83fd3c23591b4f6465397efc2add12a031fbf0303022a940c8c6d4e6e26f5e60093059e7c6b41da353644255dd26614f2a" },
                { "be", "fcf93f0f1835522cfd4f938a4e1c24c3c840bb95044536549ab17c5f8f21fa61a85bce057b886ebab6aa33fb6244b0b9b14eb7dfd845ccf945eb106d55e3384a" },
                { "bg", "987917666f7e16dcd4dc9e1011c7abc87d3d8b3e72d226cb659fa72f6ace3fd2eeb6cfc99f42eba3ae91e493413f9e91f13680ccd441a5591c21f27e9faa901e" },
                { "bn", "98014169e7748c4e39b18b9122280d717777bc9cc12fdf232b612cd727fef965953c9d0244c513638f314d88668d7bfd56abbfae20f7aa0ab7330e499563faef" },
                { "br", "1418f1c9600fb58a6c0d734c8abe7569912ab22653e86844b2c9641c47f7a599e98018a0cb845813259436e94e0152c8ef5cedccc2b1590353db7839be279b8a" },
                { "bs", "ed81a264d9fc83445923f61671fe1708d90fca3e704c43005657c5155129ed768c214eb3f1d1aa197747b6aa89fb265cf51e58e48002c765f7677a9f8b530c5c" },
                { "ca", "43b3ee08f5be549eec8b378e5af6c1bd150c3a5d184592173608de2d2bc1c4283594a9076307662f240860f513abcedbd44168041a8909726af92ef5ec31cd73" },
                { "cak", "302b584c7102ebc58ddbf612d1f1004a5f647e822dd628fa6106ffb5b1c57755e960b46abbbaade2981744afa5a6907276840d09647ca273e1e5ea659a0fbb6e" },
                { "cs", "3305813ccd120619051cc142059580e2e4912e8239a474a3dd7fcfc925f84d0b7b363a4fc115b684ffc6e7b235d710577c35a590cb3952b8117ac1fc28e52e99" },
                { "cy", "e309b968e449abda5dcf053889489d4dcee8995eadc859becb2f5df6d75036dbd797785f6fff652a4696c27ba2142ee1f2c0056746d35eff64b12cd545227b17" },
                { "da", "d74378f218d962e9d3f760690809aacd08ca839782a459eec1e875171c068713fa0d8064b86894c34767e7f8764a9edc4d074a10713351a68abc866a098b777b" },
                { "de", "ffcc0553c9c15efddda91edac173f2ee29bce13d93759041adef9e2fe72b7630d9d628903021b3cfb2bb836904c43c28941a7c67bcf2c7d0f1046c120aaa4af1" },
                { "dsb", "3027abdf8dd3d7d3fddad11615ece8e06f8534f64c0cbabd746aa3680bd93b942ec7f3bd7d818f29efaacb6750a95d413734007a95eb001fffb3746a321f274d" },
                { "el", "d5bf1b37ea1ffbc3a4c7d29a1385e442f8cc5677b7deecf208a64b30b0c1e9959c9a332abee12767f0f16dade8e77b971ce68f39cee74cdd8a3881c4fb0c2ed8" },
                { "en-CA", "37b150c800f70c86495389a6dd5f911f5975924490dd28bc045f5a6f822182aaa1e54e13cfafc23da5b7a9173c6da4aabb0a9b7687aba8d385421714f109a329" },
                { "en-GB", "cdd2148ff6493ca7af7b04bc7dedf53ab1a0efd8f95b860f25926ff123e84e7e5e1293c31c411c1b021365c7571b04da8191da1f989f44bb3b82acf61ebd337e" },
                { "en-US", "16eed6475cb915730b6bc5d46130368aa44ed5df8c8500375e7df9196ddd9712119b47a91c83e2fb9eb91971d52c4f6ef0021e5c766496565d16eabdb542357b" },
                { "eo", "3b72c935a8a8f4636dd609f0bc069768cae2eaf65cabaa6451da64eb972c61a8598606149bf638ca9eee617ef6f6766359e20c7fb1f9b5532a932a7f6fb43717" },
                { "es-AR", "c1f74ea2dd044cdd28b33518ffe9538b512b50fea077329ca3ad6a291b4c4c9dd578ab22687721ea0bbb609069e87b81ceebf833bab660224896ad0244daaed2" },
                { "es-CL", "f6a4fa8695cff6597f7f8d1b98eebe9290d339be2d713325dcf2e1dfd3381b7963b71450773a4e59f3e75456d80fd57bb04e2539ea7f9d51bcf074a383b0fdf5" },
                { "es-ES", "260cb8440d505970a63a7f5f5e0baa6ce1786062808886f1c6efe7b2f8f85f50547a36c9ff2bfccbcec33d6ce3f96b308ff81d714f2991d60bae14d76ef9ff0c" },
                { "es-MX", "69c526ff986bc3d03aef45b569fd40591f97dded51186f67b195029e953c9cedb769cda6fbff4b4f77d147154ad0aa7495989fbbd46988881f7ce19b853c06c3" },
                { "et", "4032862456b7a74efdcbfb6a99dcedde4457b2f258f76e881053789ea00a5c458f264c7aa94c35bdace5b5595f1fa7a57bfbe38b2328dafdcab979bb3dc7deda" },
                { "eu", "4ac221016595aa57295326b7687ff4562b64d1a93f91b250b95159fd6cad1a130f1fbfc6d1ffa7bef7601f5a93680cfc69c4de527197e810b0b949a7b3eda028" },
                { "fa", "1f7f77d67c8bb6e3e80e9cad550758ad0d00acf6953a0e1b9e7a653b0a8ad13c35920eb9272c61836c31f2bd960e66bb61710720990ffb5fe8c9719162fba94a" },
                { "ff", "2bbfcb45ef8470ca9264fa0d0d2108e9c215f7957b0826ce81172eb655bbc3af862df22bb7e665325aa1b08cbb0a4d27131a36a2188b59c721f8b36eefa2e5b5" },
                { "fi", "a8fc6ab3e91ff78a9451c009303110a666f9f877bce2cb2a74e7188960a666eb4ebbabc3e10f552e50982e1550a598cfe9f3fba3e4aa936b12182bea8e820140" },
                { "fr", "43e441454edf35f73f1fb85f7204ba4babdd6114b01f601ee1c52043ed1f24dbbdad7cdc0d54b8daef06a0e6b154b8cdc708cd7a7f96225aafc463aecc63700e" },
                { "fur", "3e48f163dd0fcd9ca356e52ce872127b49586f5ba1148a10cc29f474663bdd24911fae67ffbfa1d7739d8e72c1d295e0c125f1a8b24bfb2a97d6e61654d02297" },
                { "fy-NL", "76e0d2bc43d34e11e6e743d2e8d4b0de9a49f444bac1e7eea4a725437a5a2f47e82ff2175103db1df4603bd6829e363d41af8eeeb7434cb871c4914801f9d6eb" },
                { "ga-IE", "01c2d4ae4a902a02913ce96b685b20f4005e2923fe976e882ad480962cdec86632ab04f1adf6d019746e9088b0335f5792026da419c55c41d7dc4a8be1c7f0ec" },
                { "gd", "c2fe277616ff34c1e5d771159fb98e1bde03941dd1e214fddfe6141f40f284dc87c0f35cd59d60c2b0c3e4c92cd7cf3664dbd32c9f1e1c7dd777934652790b8d" },
                { "gl", "f22333d7e3eb6937079c7b22a28bfe8bc8f9e1f31d1d1c137807f3b145dddf844a02232e8586098c96b448aeea7db9f70796e1ddaa31393fd06ce03ecd7e5ca2" },
                { "gn", "667ec1de3fb5f9198d718b671e7a0fc4c47f80742b8982bd63834df714e3b297207e50b0773535e0eb5499f5a6dddcb813fbb8ed64ce6ee5154ce6baf67e52ae" },
                { "gu-IN", "6b1e8d41ead10d2505d8a779d4806a68818f5c0013ff080c6a2d09b3f834f93c2a7aae3b061865805d9aff7d33075ca1d215a1df0dea4ce48127618680156ec4" },
                { "he", "c7810edf6abe4a907378ed97607bf0fb1575e9b7f953ca12744f5886240510d69ce45749ecbf7f213292b38fb69521487fa1453b5769413f77e2250c546abb83" },
                { "hi-IN", "53a2c320b589cb18cf36e3bef6f558b169037fe7770820b1849bc1d6f0481b2a8515eb997ce6f0bfa73fab5b99efa0990d685b2962f0a5805656b9e52512ff45" },
                { "hr", "108fd74a03624f8b7d083818fcd938e6ebeedf8767e0259858eaa21034e23a884ca4633dd43c30464e3facb57568ef8e82843cd26a19d5f1d9b36292fbf1c25a" },
                { "hsb", "fae0ad85671eb90f28b9c4b5a86e90cab30993834dc1aa6073122ef77a34130ebb3525bcc4e4a7085460b5fd1f228844f5fdbbc3c65ebe0e4a9cf05829a82c07" },
                { "hu", "f487af7e861de6c931e357af09f6699a89c56a03437169589231dccf5ee237240a608e1889fd5c036ee29807eaec7d357f60e3960631eea50f7191b781b23397" },
                { "hy-AM", "78e32a3f36a2e626accf781dcd9204e1f9c058b73ab4b1ec1b1c97abaaa0f4ad922e4edb36b1fffa4e3a252333f084f8e3cd71708e1d21b334f8b609effb3ce0" },
                { "ia", "21d9768b51091668fd0d150785f7e5e8cb4564f90268491e6c4f2d61604202896ed21976611c28d640a9d3a9ea014b1afb090fac1d4cc75e5b73859d76f6f71b" },
                { "id", "d80bfe74f77e5c6854d1b641f9e3bce54f39c813f8e92f3f11da73f0b458fceea26d8957a84b30dcb9111a0154c0a3abedcbe6de36c0fdc7d68644ca560a5057" },
                { "is", "205efc25c1ae295db9d5b0e11d337bb73d6c6b23e11e9a84af5528521e6885d02f81d06f08f151b2babc343c60dc6bb96a60faeb41a4f32c768fe8ea1a4061e1" },
                { "it", "12e2d3d155caf9815a86326bd2f5b9c1d093b11d344db75ea55d6a88a3b750f79ad9bf16dacc3483aa3b6c34b341ff766efb58ed4b6df85f78bf22c2f969bfb4" },
                { "ja", "a6fba9c685e1d029f2f9a3e97593f9a74e21b5bdf18439f905571fcc36e2ccea1c84f28489f529610e9bd19e805cbf66926e19f9211cc1476e4ef4190e63f73f" },
                { "ka", "e801490f4de4732d185a90986b666e03b10bc376bbc84c505e4f6e322b1701fcc0afe50ad8eb5b486be5aa58dcc5031bc8b55176a6ebcbcf8a805ab7fbf2d8ea" },
                { "kab", "f741156092fb0272ad31e4de6b59227eb60d4e03e4e50e0970122bd4049db641188aefdc7625a4b284d5f979b1e8450b570267408d12c283de479d32e1f07086" },
                { "kk", "f6fcff50806512d3a2962528acab49c4e63e0efd6d4b2253bddeef4455c00247b694af59960d30a258fe333557f659e3d8722229fe66265ea51fee8628e03d1a" },
                { "km", "d6ebc6f40a7588da6627d3e21a15568661ebb094bb66632556508ecd4f8119892f0778f75ca5f3a1430b6afe1760e8c132804c65ae37301bccaf4e4cd355dc6b" },
                { "kn", "2183f21c33d6e70f2e605c2c576f830b946b51c9a2ab0d136d35d3a59f266bad755a6d4e55fcf67cb4b60d8d78faa094afa4abb58851dcf0b93ee41d5578e224" },
                { "ko", "43735489e174e8ebf3601a6ddf8e9ab9e8dc12ff29b10dac25b44e0caf579b8c98f98cb99e173b91ddb235caa2e9a8fd97b2eb2486a6903abe28e060cd7aea54" },
                { "lij", "fa28dca6a6ee114b8e4529f02ef8b62f8507c62ad0feac28b5a7e622ffac45de77ce7a8e11ab28a4a67632cf19c4f2bc9f944961e77d90323518fe4b755aa68d" },
                { "lt", "13424d721c44d34d50f9baaf20d10b02ae81a2eac252229a6253d15da2fc10b44f191180bd73a22cda49f08e4b8573aa6a3687d290ea460bc6bbfb16484fbf45" },
                { "lv", "20c94190333e671839f5e1806a6f860a53dd01c3d1ebc9a3efe3d123393259deee153b969c57722ab616320947517412a76f96e8ced693103087b2e8b18c99e5" },
                { "mk", "450f5ae0510021bc51d6fa342cd86dc220fe388b47c1f290a2d6937e37dd289bff79f59a15610f42be5a070433aa1aacdb746e68598999ba52ff4ef81092b3e7" },
                { "mr", "6e510bf8b4bcd874ac2bb88a62536d62fa8ae836bfd0a34ea082c2e8c4c1ddc6b71cd7fb43490ca0aac37df867b48b23a705eae419bfdc45e740c39777721dc0" },
                { "ms", "ffc344a9c7856f2a932307bc28f2d04d1b9c43f7fa221e069887d11c729fa3d8da98486984e2492cf0d7898a928e8ba4088fc16c64db4cfff96d2fb71e9223f6" },
                { "my", "d0be4002b847e3180d2fd42c1c9831cbbbbdb37feb3cdc0e61e59a707c06443c710a850e169df5d187ccb22dcad0049fa6339a1650a0c64d25a76f47eef31169" },
                { "nb-NO", "5666c5f9107fe74798ebd3d280eacbf06ab2310a645f598059e39d52fcb0633b9c96c53cef67f572223889f71504f3064f36be591fdba2a0445412546a7df1a6" },
                { "ne-NP", "80abf497657ffec255e1c535ee586903b40e036035a48619c48d0d388a423a919abcf8915ed5eee8f2c9b95be5a7be53f8206c7f3d0f12041a710333ccd93a29" },
                { "nl", "05b67c6b97be4967f496fb17f0853fba0833b06ba3c3f8d6b721d861495ca0e2aa2ef45e2017fc324155a5290cc69281355ff1aa337ff97fed8c39a977287951" },
                { "nn-NO", "475cb5cc4828928ee423fa8ae0ac0b51aed9fa9b6923aab8e0e8e310be7ec6e7b22d8c86d20c6956eedda9a52e5f805fd677716ed3a6cec42ada98c347d17363" },
                { "oc", "9cd84f584b91d2561008c32f0d6ea42dfd1ef99f75ff4bfb74af80947e3e03f0aeced1745394926c9ad2c5ff3e9048789e228ad8d7066fe0dfaa5040bdc55e5e" },
                { "pa-IN", "706f23e840fb6ed81d44a42d1ab404cd4b43c22895eb403b564810abf63c57adcf8ad4043990112d1dfdaf314fcb4f102db595022fb69f35ebd871de21807796" },
                { "pl", "a651aebbfd261bded88846a44123d1a4e864696e591e1e4680b782c38ad946899ae5b7bf88bc2cbb4f14a02671acda9f5cb6336e6ad2ae42bfeb9117d2b7a056" },
                { "pt-BR", "468f3865bdf33e7b068577d243c8963e6d184e117b928fe36e3e1cacdb17238cd6f2049da533698fb7d50d5c49147bd114b7624f8d1d48c2e5e6ad5c6fca2cd4" },
                { "pt-PT", "b80c4eb5494b0d692ddbd855f9b269b3109528c46a12652d9561c0b955228271327481294e88b0393e4b442e77a091f395d6945fb8687600bbb7ebdd571e4f3d" },
                { "rm", "ad2a85d05b751769c353f1343e0ecb50d97254943c36213e65ebe5a0198ffd06f58887b9ce4a0a404779f1ee83f8c67a343e29db4e62a6c1d5a65f035769c1fd" },
                { "ro", "fe3e560583cf84add05ef86f843a014906c37b3fdc9d4f67a125e56895e525198877c182679c10deb9999fbae8364ea8cfd92a07f22576b62efdeab1cc1c0749" },
                { "ru", "d2579b8f8a673103c286329152c7a3bb9ed1a19d6be84851c020b4251e8631b017fca4a9f6b7cc48d1cd09b8962252519291c33ca985e261c9122de2adfacdfa" },
                { "sc", "edd6e6eb8659f0525245739bf7f1be9da7d780ada5117eef706cccc3eacb75b7331af88e213a547197af263e7166393a5def754df014c4517a3486b807622f7c" },
                { "sco", "f9151ee61521a525e739bb04453497a1d353b523c645392f3f55b7bd3c29b9923485e66a03620b891bcda3c32f855ed2ea18c55422e292dd6f4301aef85a1d12" },
                { "si", "df092e4a9cb4e36010d5a92f359662215b334c6c1810254b62e821b8793d0b86bd07fd3100659b035cc599efdfa745968879e46771a43e028e4c33f5dbdacb29" },
                { "sk", "20c57662006ec6a8baf43f43db0a57d1f1ac51529e3cabc37f1eeaf8f79ace7f7f1355ad2f96e40d57f4e8e7b7b6b6d3db2ff07032c3cfd680aaa7c52cd0ce69" },
                { "sl", "127189662612073f4a9a74cd148abab8dd3e3c1c0270908d790a223ffc4de8db1c63c6c4a5effacf429198c17bde4611dca96c1af7a232fbe81d1ef6552c7b54" },
                { "son", "9e481de48a2b95ac2c115eaaa38ff51184d69870aeefc66baeff6f129504bf68a21c3da9aa7fb159b073850826c4ed092f52c60d7dde3eebf8177275bc5eb8c9" },
                { "sq", "fad8693d83e3345ac892dc260e7b1403ee68b27e8d41a71906e01b5f82b4c23818a2ff5b3527e7254a309ab9ea58e6ae9d95da5faea2d302b6e5a3005489d968" },
                { "sr", "58b16a4de6c7b0164ee6f5f48d7c926994980287515414c5d84309781bd7b1cce884c5053087e3068134fc2ee4f6cce5f64ca79144b17d4521a94170f05a1fb2" },
                { "sv-SE", "8d0b2a2931f982026fd00681a84f5bcda81e88865ccb70bbe660d9418509e17071214e15b99aa5eb330b953d1f5f3bdc0e4a235c33c1650de876e95b6ea4a3c7" },
                { "szl", "d99583c4639bb2609827152de6c49222efbaadc55fcd475a948b9eb293550479aa0e507d9aa3599fcb8d8b299ad155d848a9a66c010b867a13206b305bbd7574" },
                { "ta", "b8495d28ca4ceab9d12371808d635075044f8a7fa0b0950beedf821ee5719b919ebb9f8200e3e05fc41a6d4800c7033dbd9b9acccb098bb65d8c9e13d32de55d" },
                { "te", "093facc0c9aaf7d216b99219ec0fbd37b0a45d2bfbf0dd6c2bb6d8a51ea53bbf990c396d1199406170aae80934bc3996181fed97f0b2125b727fb84e9bde5fa2" },
                { "tg", "6f18cedca7e9c85bf2a564cf6d0ed41ac84f23583d180e95cb3df2416f0f45778c56e18e48b1810d6fec22e71d7ecd2265fc55bfbae66b4b549113085f697cc0" },
                { "th", "6ca8a4c99604b86b7d7dbd05871a5c882e3c9e66eb6eae3c10251bf2fb0e3be7e1f3482e97ada39b59984818879f2d9a9d1ee561f090ad1d55f04b799bb28fae" },
                { "tl", "6902f0bee238c64db1328be34a5dc3cd4d40b1ab3f64d81ac859663a80cf98b3b93fc3069b21a363cda3eacdc9e6a3c61a8446be5230bb13d013ac32c78df5f1" },
                { "tr", "ba2a6037635d267878c7ea458552e185e9fe40f7fe7c5003810ea1ebf49b0fe93daf75857be1031a85d8f2348da57557ae59e22303f59d6be38ea0ef9f1c8c5b" },
                { "trs", "cbc6b074f1d7155927c3496afac8ceae46968298a98ccb09adedef71905b0b5370e179e0e16af1f02f10297ba416ebcf969ebdf844a2f5b69601b20eba7f35b8" },
                { "uk", "4b4a6830db2d91421a10fe25d0fb8d48cd943db436beadd19729142116df05bda173fba445be72fd00d7f45451e95be46b195db4c470c14f18162bd5a6ba2257" },
                { "ur", "1558c822dd4a6b846c2db6246d4cc427c95d1168d16da337e2d4b1e26457bd0146fbc8dc7c4601f72127a253afbc41ae1645e7f10f9322b053741043754900db" },
                { "uz", "863a5262de018e995ab342d15fe22d87b5de70bd11392d60abb0c896a0592dea827770ec3dbba7516785b9a811d12d5ea3d4736bc1315d8fb0af222ef6559170" },
                { "vi", "61121e01e80f2e0bcab9929b131ffd24ac7988019d3e308ea8ed33e85e209b89125acaac188556a7a27fa9b55c4e0c68ff9c337957a51fe34bbabec123a3ae5d" },
                { "xh", "f6369d5fff2d384c21d5880f98839f24983ade84e4e7ac3e1ceaece72d0339aca6373ca237606725e3af5a43cadb63c2958c9ae9b2d949c8e1c3fd4cf41b0bff" },
                { "zh-CN", "d3c8d7faee1b3f13d2dd63d6e4bdb20651e83f82cb551646db3e1b6d59738ccda72825ef8ab10b900469a096820f48f12a2d99a0341ba66f7cb167e065d1e5fa" },
                { "zh-TW", "425d1b3a97922161213a8fcf81765fbbb5983c19e3067c6ebf0c40a82276a6fe3f43e88222a3999764b33bd3156e3f58916934fde8e0a090aa75acfce3fb1c87" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string knownVersion = "116.0.1";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox", "firefox-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                response = null;
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
        }


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searcing for newer version of Firefox...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // failure occurred
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox ESR version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
