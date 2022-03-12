/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
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
            // https://ftp.mozilla.org/pub/firefox/releases/91.7.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "78bfad1669a8d68737c7fecd01821626daaaadf7f4a6767e2d2b61c552e5f63cc6583e832d0d47d6af5eb4ab04a669774530d2635c4aad2537208a12231ee9ff" },
                { "af", "4de9407ad52fcfeb81d1b9080fe160b4ba0f750c1767355a2e6965f6564f94fbd8247f8be8369b504de1964adb4884b11fa02d64373554e41ad3d1d653714f2a" },
                { "an", "0626a859cc4c3514521483b300eb76dd520a22aa7a08e51e8b9d44ed1553a2212bee83df7135eb2cebc29aa57291c7b2f1d7b86fe5b0b3be0360b0e3f0333699" },
                { "ar", "33556efcef9aa663566e9fbcb66b8ac5566d681a46fff8a25d35b56e5c45c51f49c8bcbef733a4c906cceecdc2cbf2dbef41e2041eede99bc81c8a4dc666b761" },
                { "ast", "c53432008a998eb506a9ad2d9540fad661731a3cb2de7bcf44fbd1e33b425f3b73a97f4eca4af1c3dfc4241112a6fe00b2fcd22daaed212d8cba06a6dd71a3f4" },
                { "az", "9baeeca97aa533be06fa70fe607210964da609b0f3c4f1f1946e2bca31d342adb56b3d49beac161e7023efafdc3037d68e460065bb2c256aa0e04432ad064f63" },
                { "be", "7586311624fcf3130a1c89f5e08fd8fa3757f686cda2a77084f48cac570ebe3f9d98c9d611a285618a5139d6713d7e877b3cd794d178e6a7547fa0d14edcf2c1" },
                { "bg", "b40b3354c3e890ad3aa845837dad4e3f4e5cf9f8753a8838b8205eb6d8b748f2157899f035416e267614523689c1fb5a0595591a6c9d19aab2adf1950bf14034" },
                { "bn", "ad538f6894a77927a1edea48520a30c380abdb2403b062d61cbe521e0475f9f272f460c664505e398f9763756194a46b14aba979b363629a940475e2fe455660" },
                { "br", "ee1612422c6190532971946482cc074e3485dea852c9bd878ed1af3b19554907716a15ba9749d924ae69578e76edb35d283ea4eb294cd9a108376103cc85c130" },
                { "bs", "1eaff60bbf1e2aac044a48efacc1229b6d6749cf9127b57af2aeac9a2eb8cb5ca3774ae1bc5d05a8d862298d2d74f8e789837ac02db9a92a537bcfba046d3759" },
                { "ca", "5e0d89849a73a41c3dcee0986ad5716d29fb637a8c9f836cb98f2f6d9029e90fc94973138a0d1f3107f2e47d39c9f6eaa164ff22be81d99e93ace8811c56ddb4" },
                { "cak", "5c4401eadfa55f6ce33b61c489e7e4329391242f7371dfee17f03d0df2d97d4ec57e172acca79540dfcfbb63a9bdefa2a04f7379d9ecffee1994175ca73a1e40" },
                { "cs", "e77c651aba75557a2fe3b99686a27673158bdc7efac500421710f03edd4beddb25920d46b42b9d436d7805e64061710b53330650b73d18014fd68c7515361176" },
                { "cy", "732855939933cb72c15790ab480d1882cf1a006da94858e9505b3443071256d4fcbd1ee8efa702a3d1e7f7d11b9f17de019ec44c7561ae25230f268b3aa6976a" },
                { "da", "9118962732a4eea4b2b360ef8cbf397bf9fc0ae44fe50041fc3946bda97b1635719dbd0d2b3acae0ddce9f653e425809c75ee406929deb73e6a94f2e643a1a5a" },
                { "de", "e7bd441aee74ea96e87b4cfa85800a61eb463c15f3f755e4fd049d3ed398d08de9a5e1143db67f00491ca2fc4828898650af4b0c7b73a264da835058ab584120" },
                { "dsb", "f540ff0350b7b41440796b717f4465c14d3b799d2b23ad27d60753c95a6fafb2f4645f5adf23613c1ae830001dfe886a15ffb2aa74fc9d208607306a4e2a59ab" },
                { "el", "ebfdbb6b67e73d9e3a8501fb66007bd1cf638e4ba06122c0a9d6a5077449ddd249c907a3e042422f44247f54abcf3cc8b4e971b761ef44dc3f825675e39fa665" },
                { "en-CA", "d3ab2d7af19dd4d0d9c8da6dfe459fced2333638bebb8c87725f1c5e645cdb05e0d43cd71aaf577b36b0c092fad02071cf1abb68979c01deefd930a15f247bf6" },
                { "en-GB", "fd772cd7d8177ae67f4924ad6c4352bc2d839a0cd245d9acf762c5322696989c30df1952c5bf3cf09ff382dba9c991895dbe54a9ddc8fea19c97ec9ca3de0475" },
                { "en-US", "e54ccf2c270ac3a7cdb1254bc1cb0b7abcf3586b93b0639c3244fc54eb4633eef7f52ad3339ec39c61187866479bf42fa6a85b9139eb814f1a276ef449780dc5" },
                { "eo", "b545dd1b95bf55f5ee3db30753d693b4ad27cab5b9ce50553c0df2696926ccb6372598c5dc22f0d42a2591998b42d7268ae50da81216ab98740393d63ad4eff2" },
                { "es-AR", "7b68c39bf5bbdd382b89fe3c7b07e979d60b81377958551a55f7cd6f4d92f4dc5043d18ab0e2bf66d32d95761542b5b7cf0ebd7cac9751a0485114c62aa68fd1" },
                { "es-CL", "85d1be06b2f264dbe49ff76f2ece930ff83249b3715564ef848263ad5cd36d5b5675acd7d7275be200b00e343addb65abc02e61792f70056c129a0c09e075898" },
                { "es-ES", "4ef468e05986e59369eb9dfbede580e4c1102d8adbad4cb1187bf72b9f7f851356b7b41082bf33836211e95a14bf2d2f14bdaa9ea254038da0a0e785b50022c0" },
                { "es-MX", "ee1f02d436685a55637f02a9eb668e1aa24625dbb8945f540a766f8d008a30caef39bb2d0ea9976ba2b3fb646e42413d562349dab91ecdbd31b459ec081b3140" },
                { "et", "5bd84ddf65b783cf61615a35aed23deccd249e7ca910cb2d505e443452b380fbb4e1c57b767c12d49fbcf1041a476d4772e234ded571e1892682d0b2c3eb8b07" },
                { "eu", "3894fbb50c9f72ba617956a155caf641daeeebdd13b0f8524cb9905e330a7750b5d0038785436568db1cb1300e512663513af4ec6fb26282847f4028a5b48bec" },
                { "fa", "82832d4158671ec90ca716b38b16a1bca3aa473e5ce8d1dd976f2f671658e01e89d4fe5eb8605423c1bff29a843038d9c83996477ec3ba8e1210ab327c1148e5" },
                { "ff", "6654713eb71ddf79c17b372db84c013f546e8e9692f6a99d3b9f53cfe6cc9056f8ee39c4a343fb8e9decc5f5bf4284ee1f537fea83ad7023e190d599b4aff400" },
                { "fi", "2c3563f4174fe37f358eee0dec828484df37beb4bd1d3e75bb179f794def0c8656dfdab0a84db0f408c04250a5c6d99d1e20a3eff2bd5dc39d64bb93c46bc80c" },
                { "fr", "dc19ed93ae5d53023b9c1747c2c5344bdcaafe9568a7abac18085ef601919a733d700fddffc7bb46ce18093cb836b9b551109729d2eeaecc11a066760670443b" },
                { "fy-NL", "1764235749e5f871544ade9d8476a825dd0aeee068744444b4b054970da65416c80adc16986c058ca29ca0943b10788893fffd80a3d630ec477146ab95b8b3e9" },
                { "ga-IE", "bd77e3f8947384e5e3ef4972831a9d7fcc8e1d43d203cc8c51ed39b484624b138fdfc6bb2ac5ab3f6f6451a9c5850694178d2ab68696a83ea5ed9b364d23c22f" },
                { "gd", "3ecf8249595ceb7931dbbb2f4a4dff708eaeb4bb814c8a33d72186dd8e6bbc6983929efd3b9557edcc027a1682b1b3211d36e38c0dc4db131adc8fd095cbeb58" },
                { "gl", "39f6fb8c2deee2e3553398e9ee8821206b136ff1fe0a29dd6b6a657ad01de3962713974ab36d49386c3c3711a5f7fc3c6f8f9e290953ca602008b7dc9d0bfc51" },
                { "gn", "026aeebf132a62db386dd57d2476bae0e3710dbaa80a2f03f0f001cc69c7a793b1d4d95e41509af8d0c7c8bbac552a6d73fec5411070e0250ae225eeff672e92" },
                { "gu-IN", "8f8a476dec5c1d2360f9490c02a11527c6916a0b0e2f287b3fb0c89ca64650416dda65ef2db37bf24a0c9337fe1171db10075bed17857d7e5a2d53291c017477" },
                { "he", "6fa919721771d00a46983d986a0a90198d760b3c23e56abb49bb56e8efa1851d596c0256211e1a302795408236a8ef9321988042e8f3a0303c5329c22235913f" },
                { "hi-IN", "e5c9468ddeb857c500a6fcb442cc079e03547129c4efc9e0bdbefaac58e821daf9338afaac366a2d01d69c9f126b7354dd339507913cf7febcf8137b88ee1552" },
                { "hr", "915b59451e6a6a00dc5940c0323e1bb3d32de73fac597e54dba2681d785406a78d117bdd8b482464c60731e66fc62620a0749c2d12591d666bf394e690a8be78" },
                { "hsb", "b9d15b5a648bce0fb94301212e544b0bdcfae86081de4b12e688b3dfdad151253ed2ac0b118ff4513e0370178dbf7530fe2df541322dc461351a0dae777bcd57" },
                { "hu", "4cd53cff6093149a5312866ba9a6286f2f8be8b81506ca9970bf783c0e68071c21e91e530db532704f9b02348915108b6704229135cc2cfb12f180a23758ac89" },
                { "hy-AM", "43e4e5e6c10f3b076e2abc4d21ceb52f038632546d0a39b2f9cba9aa0de7d1001cce81d8f4e5cdffc9806826a817dcaa0b73fcb70371731c612251d19b882713" },
                { "ia", "55d10b13902ede21268d6a5425ffbb5e2bc8114b26e524da6d18b88d1e2bae4c2cdb0de63c14719ef345d3912b058c7eeed1046d833c616b5d1c7ee781cf93b5" },
                { "id", "35b0e170dfcd1052a65280067902311d454b7882b055d3ca39f6199f3c2aeca1092970d964a10649db6c185a1e7e6d13d3d9413522f4e894b111c79ecd8f8322" },
                { "is", "2a11e0937525f9a4b673f07522bd0490258613bcdb70587df8b52aa79a1799a4e14f4e0532bffc99a1079c14828934abb4a397cabec78969e3eb3a418dd456ff" },
                { "it", "6f3245063d5f10e755bb8de77684e3a449f7beb2db425571643807f3ccb5c2b928c87a920bc79a129b0541d4aa5c3644b4c1a619a14fd8cad1ee63d4860bd9d4" },
                { "ja", "17f27038c6edd79115d9481a3075daf99a8c6723cc2c49fa57517cc50ff736c1406920c6d7ab73e9ad507540b0bb456c0ce9201f5875a59c10d58d87c0399b63" },
                { "ka", "05eaaaa82c3ac92df1536a201aa53dd40e97b9540fc5848ea052e3685db5f92b58e736b39edad19b20669a0736c0f22e8a552a32baf00582cc4f1a1d0368ed44" },
                { "kab", "8fb956b6a11e2a00e46c8cc22845536a0a98e096a2d6ddf34d1fb7cd8b9576b7cb68b286a96de0b6d88466abd4480aa329349e6ce479b35938c46a4ec5ae8288" },
                { "kk", "34ffd9da661b34aa58a36b709e823186f627da2af86da3cb83dda3df1000d12b7fefe9e706debcf2f9b06d6f754e98d298cbb2bdc97358a67d219b9a732fc55e" },
                { "km", "b514e730cdb0b465c86f69333b59eedee8838ca55719239b19c40cb73c98f20f9fffd035d6138d5783bd08e71c177860620aad42833c69ee153984a7eefcd52c" },
                { "kn", "96284d32d577f08a0625cf130a0f4717a6930a35a0ad8b8367fd92efe1fe69d40df1a5d6ba8f5dc43d5b393b0eeaf35f3200e20cbc7393948e7a405d2b5c67c1" },
                { "ko", "4a7d8837c0061ad6df51d6d5646e70878f85771b474d23d006a2f842deecaa83cc662efb8a3be3c01c22fa582d52110f1c5ac1f9d3580c873945660ba0dcca6b" },
                { "lij", "5cb18cda0b1eda4bcb83438358a355fc130f56b3c6953875a7afcd8c7f8c15eb7793fa397be7965af5565db95adfce17a12a4dada64a1f6f4568e4304e22aaa0" },
                { "lt", "243836e748e2c2e00a31fb84462008dc6ebd0b3c30cd9c5431e45f1750d0786fa848a5a53291a713a19e8964da0eb854a68d0a86855336416e62d1e53a363f55" },
                { "lv", "3d0ad2214fe2c496486ec1a6be16b911780d3f4877ae974102685045dc18f1c9a9ed010bae9f9e2e9cf90d34e6250b45585672e7a9ec56e151008329338b989f" },
                { "mk", "828c9ee5775444b6e361a09ee7efbed26d0bb78d80537e929a36a5dd5e8c95f6474735d8dd17ffbba46086b18a7abc3a3c88baa5b26c1503da2450ff017def99" },
                { "mr", "ecf8a44478d1454d630b98aeba8fba5814424a8705c1bba3fc355c29c7b0e2be00b4db090c4ae6d05a04aad0207b71592f22dc478cfabad625c28e24749c1afa" },
                { "ms", "38ece7dfa1763673cf21341ddbb025657b60113beb5207623956dfe04e478075b1b2481f6126eb8ffc61e67c778885ce3e494cfe16b9555735455df02cb2873f" },
                { "my", "5589a9ac35471c7330e8cf167889a0ff47101133d2bdb910c0813b8594dee0697ec9b18346a8bbbaf376449c8d628363fb6e9cce8d0e05fbe2f2fce44c57817e" },
                { "nb-NO", "32f119b5eb3f0dfc67aee9e36695ae1e30288747792ba1df78dfa5f558b77518fbf193c7acdc8cf8a3deafaff37e1993fb75e6176cd533aebadefd038ad6f857" },
                { "ne-NP", "80ccf6353dd1ba2359b670bc173d807b01559ce7fe3dcb76d575f1ab521844db65f83fc0d83b4a2cd9a66178b8b6f4af049ba0b70b1a94996f2e4846719e52e0" },
                { "nl", "a7731318044242816d6691fa97097a6add0eeb3ecb0d1d943655e7de3417cd19418ec97f0a7831a5bf2c596d7521b249064b58bb478348412c04693d2036f60e" },
                { "nn-NO", "b03077799019c3297f09afa94e328793af51b92395f2635ba8fc4f5fd6d45e04739ce29b41575a6f5d0e31643ccfebdbdf1c26b6b91d91211b488a331135acf9" },
                { "oc", "601fc1ae580febd79731c9e69eba07f41b88caadbea018cb0580526cb357ad3175830733c2cea3b74834f96af07a3a11268c974ea3f845f8414c709ec2ef3caf" },
                { "pa-IN", "ce9a0d1f471867dbd425288e7a74c2ad27aba7e35578e40ed12bac898e8a83c81ca951604c534ec76acb88214f8bfbe3edc8e62195d79c2425729242d35072ef" },
                { "pl", "4e10f12e8933c8343de76f94c09a51102e139b4538e67e921c17fe833f764b3b4969b50a1a257878e3c8a71f079d61bc7f20d0339982b8ae5b66423b0ff15f0e" },
                { "pt-BR", "2b29059ad98f4a9ca354b065d305a425a260aa6c1469ebb79d7faa4b872eed7d874d19fb3a55d0ab83a2502b4887a651342a771977760420fc31a3f05babc539" },
                { "pt-PT", "eb86de8ca373e3890a10563e288610dc55502b27c3df10a62d31cfae99dab8edcc9d671ae1d841e86b0ad51c5af9669c03216120be7da7ee9bcee0a0624c5466" },
                { "rm", "b2270ebc359314b233c67b03cb51636403770cd2357cf5529e67aefc2a57b7b92c6e527e545ed89f163caa09ee86637180956a48fbdee519a4d6844a008dfc13" },
                { "ro", "e97aa239f862ae241f25857b1998284a2dcf07dfbebd06ba976b1b677d93af4d4763f03d2a1d2ac94ba36aa7757c506ce51fb0aab1c0a108d6c0905f4b3f77f9" },
                { "ru", "99efbe444ac722eb495f5383c628867fda5e43006b5cceefa57cfc02b331c57f98f99d72b3282974803c6c797d85725486faa213fbe55362ade765b541d0e9db" },
                { "sco", "6d8587534290738799436eced068cc3fad6a618436f3dec1714f3e7aa2529f3e3cbacb04bfbca54981e18f41a627e5b122b83aad76778e5ca9c43f2cc9e9e70c" },
                { "si", "cb1bccaaa52e50ece696ceb03186910449de9f7a72f26bcd2f7c600fbb5109c15666c38249e56dca22db4acb86c87c10cb5458bc6c63a4c9467ce797ca741b72" },
                { "sk", "20b18714abbb2481bdae95de34839d6424673c68e8509217a43a55d4704967c7a657a063afc1ac2dd30393042cb0936b480bcbbb9ad8a27f510096963ddaf7ca" },
                { "sl", "aa374fbf341f17203df7e6b23307eb867e41b44b4919750c90f4713ada1159265495a1bfd4e334add43e532493eb67eaea5631b893e7db56a79359117134cb7f" },
                { "son", "0054e5150a48b505d956e3f4da9d0387a096147887f5942a07525291d6872ebc5fb8fbd90ba58e96d7c0fbac4d4820e654c2548af8cb1fc4a75eb5160fe46a94" },
                { "sq", "1ca053a3551e789e2ff1a108efd2840a11cc64a0cd93f410e991533de4d66f5592cfc60a834020c191138b919a727985220d7fb51f5ec55f215a36960ea49467" },
                { "sr", "4393f82395fcbede626d2f2b78805c1f91c826f583554f23b9437636f820b97924bb11e12649ad7f54be82690f0e31485455708db90152ff8ec2bfabd8d9c3e2" },
                { "sv-SE", "8bcf2265bb0b9ac7b6c8a4208463cb6606bc4c05956294eff767a7486accc58b6027d88ed866f1d12e56506bd2754cca22e749693d4e91afcd6068e7cf5ae3de" },
                { "szl", "a6cc2cfc3fd71e1babbf12c145b108b0cbd32a9cdb32d29ad5c9f5b233d99a1555c8fac7d1028e0d96ba8956705d769ebd9f3d80ff103e2976b424ddf49a3408" },
                { "ta", "f1bbf97da883e9b7842508f3293b60ad847602f8a3a015877ffb745e9cf70898165facf8ac125fc58ea7bc0586377027beb6e7de372041d752f67dbd69266312" },
                { "te", "7ba13e22d3bf5bbce535ef62b07829645df8e5427e62f46bcae2ad8f18b44a4b3016642c98b41d21c80d3d05b2036cfdd9e746aacb9360f60b0ca14ff897331b" },
                { "th", "33795aae21972552bba4822c896dcdbc679c3a2aa0d65018890d8a3cc669d756dda8ea3ce4c9755b85e34b90be70204080fb6c365c7b4d6a9dae3d3b4722c23f" },
                { "tl", "e8a1876aa78e8af6eee849da3caf02e253116cc3be1baee5dd94bdb19750d5c0a467f76c7c662d1952550e3c84630de5e560310453286827e5c919a05cad1954" },
                { "tr", "250ea7373a9cf035413b51dbc5915fcdbad0e431d32b2dbc71b370ad3fbba38f23a001feae5258baf2b45f387912d2c70ecd863871d144ea4bfdd9f9e82bd582" },
                { "trs", "438088e5b7d3ce1dd09c081f6ab482144557bab8be52c79a6d82425a3b0d3073232b9fd751ed1be7e0a2dee4246272b31a6de19990ab619fc4768b21c164b6b2" },
                { "uk", "243fbdb98204f80a4238c8bed7a164046337cb2b685889ab75af0aa2b4342135ead78f21b3d39393848d97d4e4dabdf9acac63c13e6b564eed0ff723e16d8535" },
                { "ur", "43768ffcb661824f06e326b91a2a27e5debd6d8adc9dda6483b4c264432fed3bf3a6badda34403b53dadf034beede5499e780be6c499924fba81c8db06d19dd0" },
                { "uz", "f9a090aad2ab15681df0b200b76be341eb35e78971b933d47195f05bcb6ec261c8da5f61be92522156d9ffd70de0e3e4cf6139064a5fa89da895b33e125a7f82" },
                { "vi", "9db5cb6047c8f324e36d4139069318ad232c37f6ee5ea846172b92150a15453e9c857d8895b67708ab7fdda71a38721b6cb564d604e60a27aad84d97b8ee7f24" },
                { "xh", "90dd26badbe83154ca9a1a8dbc89012b7bfec5afc5fc0131061581dc608dc05ae3360f5eac5707e1a513ae6e560c5ff848280e455ae73c9ceee898c50a4e601d" },
                { "zh-CN", "0a8c5aa1adaf9a06fadc6f9b1e452d4a9336a8230c229bd41e2c4f584f445de21de793b74efefe295e0de7925a3e6f4572251f980f613da2af11f601fff71bf3" },
                { "zh-TW", "6dd78f9006d34ded263c45da6a52aa9e5fcfa77d1930a95ad50802020a11d38dc73f190e09de9c9dc5fb6c3ba7d2415e0de897505a1a56f80f4e3a7fc0d30b8c" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/91.7.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "2b72b9906a66a06e883a8d5333b90b51a56fbfaad07d3188e627325974989bfedb5f5da142b0a93a8e2c3d0b218e4c3cb9a8e46e1d47deb46669fbef45f5f575" },
                { "af", "f415bff8e42dddf62f56430f313d0e0c8516fcf213426002628fa23630fae697eb4b5490f7032b1082f8cac6aaeb73b8bc467175de7e6e405da1b35714b2cd8c" },
                { "an", "813f99b43a9070181e19522ae7c79ceed8a85c94834ede857d974308161f5df08bef17e11a77dda1f40ca9639712fc587b51d672546a575eaa73cb0a920356a9" },
                { "ar", "921c5c3a95d1590603cfd359a47b803265cfceac763f38822d6f7cbecd98b945db856f87e9cc330e582e1df47ccbb00266522c8a202e96e9fe992c58e64edbda" },
                { "ast", "539154468fb8f554ec27f527b5f912ef05ae668d24dc8ed9e180812499796265107572c0fc3162f56f14e83cfd7ac84462701908ec0bd2973000c50b993ab88d" },
                { "az", "9fda9a281afd0e5935ade25c4d7899ebca572e732b3a7a8438ba550e761bd14cedc6d7d306f2f37890bcdc1016090ea091493e49b9742f02e4740cd1f8f7ac20" },
                { "be", "8809d89eaf3e09321ae0aefde3dafbe2cc26a42aeeef7d3a781b248fa42fdb2bfd4fc472a76022bab29a7a1b08194391fc546153d6426b795915ba23bb45bc7b" },
                { "bg", "abe8430cc28b6eca2deb20a01d3ac00ca4da91795903a3cad06cb1750932e2eb64f824d7ee07b9c0e4c8604e09106cec1b328d758bc27557455e97626e2d72bd" },
                { "bn", "c6fa8dc5a9543dc5607e17e4cf79751c50c39d651c46722e0e70da6715ed96991217480df1bc4b27185cdf24023e4b5a7a5813f5be0f5609f949fa1bbca60b5b" },
                { "br", "61c2a3da337371834d9dfe503d805d298f332c733ca4d50ff0790cb451bdde103e5b5f21ac9a2600c8ec7fce830f022a0a7214f4116d4a5ba5fde48f0d3ea2fc" },
                { "bs", "739fd754a3ba8712c070b9cb5cafd0372357b5dd22c2f449ed7a6203aaf138f6e5f73ebb677b5405221160344c8a1de7058acd106f0b3cbcabfcd9b5dc41441c" },
                { "ca", "363c568767209dec36e1fbec9ded92b20dfb961b78d56deeac74710acdbce400cc35dd41cb8b0dd716f1cd285abff7aa882309526883b249389ed5d32c13e7a3" },
                { "cak", "d9d7de49dd3b33ead1ee97fa7ce761eb5bd88c490d6653c996b63fdc113721028e39497576b00333ad253727e3fb88f48caac0e8b2a545d42b19f722128b0384" },
                { "cs", "7d08d4ca458e123c282d89d19bbf6f2cc8cf0c69a2712306a23a1c5f1a35299f84a10714d0ee3808b43391049b6115e9fdbfc731761a2fe82359540221da1508" },
                { "cy", "3bd5fb7216134e28df16399def3fb9228d9ed6eb05d2b57e0eaa40cf0778b995a24610123a7293f387555c855bcb8fa1e7b869111bdb5fd28c6a633f3e3bd2ee" },
                { "da", "88a7b8a59fe7ad0c722667d13caeca12da5a69b123c79b37bc46d3cb095332304a9bac0e5f6c3a858f8369c888e0e5b64558bda33fc929f4aed759ce4b32d4bb" },
                { "de", "2905a8c3de005eb78dc720cd27ced5b2f56ff56005f1644dc7049fd33c06a532928596705b17cb3fb7f6364cdcfe14dae8c03b827a031122b32774c35c23b11b" },
                { "dsb", "999c3e966cd566ee089c6c1f64fcc9c75820892a8b44d1529eba20faba0e390bb93e29f244ef1d68e37520e56bf65daa88109aa76a90cc9ecbb4165d79820b6d" },
                { "el", "a0dda9c374def0835d1b67bb0ebab095dd0fef9f5addb7114c57fd31f8258ee42be042136e5ccc4271084a75a94d5c0971194c9558c7cba617e9992ef4461fc4" },
                { "en-CA", "48328922e30d877cf53d6f040f844e1ac985d70424fc1a1c26698f97c67d8af3c7d6468041a3b958934429f22bd58810c67a55cdb4ce2df4a14ede9f8592c621" },
                { "en-GB", "db80ccc567d9ad19f20c46a9da7edcfc3dee9c6a527ba8c29a1b5d9c435a068f36534f5fc0cb7f7302efe0ff186117dd9d8f083fae0cf2a97eb04932e6d42dc7" },
                { "en-US", "e9599ffe47caf0cd9454155c3d765ae147494575641fdfc7a977f0711804b88006e368b3e7196536ad933fd5ee395175c642dc57a8d253899676ea9c2ce8cb59" },
                { "eo", "34a4650c54c775271c9c7a326355566ac2db226819281e3241ec857e806f272a29459b4c03726f5ff66d0ebdfbb78a060d24f2dbd50c9ab8658265cddd16df02" },
                { "es-AR", "e614c340e90ce70c173d66fbb18b8df1c4a32328de3cb83b6b2a3bb4a8f3d7d42e20a17e73eb8f5c8d65aa61384013972b9aef24f5cf7e1cb745bcd3a60e472e" },
                { "es-CL", "171e328d0decf0a1d49aa5ad6e0fd760ed7904c5ee32c6b1c0b95800787916294c55316ed5e3195f79b8ffb91c2a9a16c54649525a2d28fea50ed21a64e873c1" },
                { "es-ES", "0d9bdf97a532e8b2a2eab5c4f1a24ed64fcd4b0bfed458c8a3ee1a226326b95dcfbe9bebfe2bbd13957e365370e6695a2a36de508399f67619ddf5fb6b4dc0f0" },
                { "es-MX", "9bfefe5e011ee1b372aa48d392ed9adab75b23933621be4acec9cc8a97cf0d5ad55372a1bacd6f0bba7d4c04151459d9f60abb1781bfb9cafb266f6fd890bd21" },
                { "et", "ca3ce300b06fd67022a99ad7b8a68262c2719eae5128fbf3adb6de6ffde8c9998e1728bcf9d5b114fb964438d83c1be11042e61366c99b81502a84a5c392fa92" },
                { "eu", "167912e7c1d91e5f0d64e82b5b2a3286ab0ff94186e1499dd7f9d6fc256285a797ae2355b1b07651ef903afd984d1fbc8bf55200508ee91a7b511e166a8c63b4" },
                { "fa", "e19d6932e02c6e9a724fafc4174ed137e6f5aa063ba311dc4f6c269ca1d2b4f6585da971437fc69f396638420f660db7980e6b0493334f7d8602d3bece2c78a9" },
                { "ff", "258194f2240eb6dc8dae725461204398793db85a7f7d6a708693f319ade423e63c03d4f677fb9137e236b361b30e9c799a121fb8da319da49bc77aa27b04c3d0" },
                { "fi", "b189827f5a086f40d53be5f6681d73de13456d5512601ebac23fcd86cd1c4781321ab3b941fe5e53c3dfb56f1f1c25ecbd8ea7cd11a4476a1252f1d4c31dd93d" },
                { "fr", "33c4b2d4084a8145d5d9bdbb567b881a5ecb84b7a08f4ca351b54043131c323b4cc90fdbaa970c41e3d82a3d06c0da908129af95abb3254fdd2b80a3606fb231" },
                { "fy-NL", "2edb251444986c8dfb8062b3d6049d31a46f6c05a65092f2f9a09d9dd007e6b5d8178585830b492d98ff2d4258a5b96da0ffc71e2063e9bdf0f6db18bc03f569" },
                { "ga-IE", "c91f8e8569d4d4cb5c9ba8cdc30dc85dfbe0569f83ab355a3d3eabc00a46fcc84676855d32f6deebeae4d5118ad0e863bd91dffe13c36730b720e8292a7ef1ff" },
                { "gd", "9c77b272745cd89cd0a19c610482f37f5119e96b355f875e4bb63a70021ff188779e093dbe75b1c215f2c6e3c9ebdad024fe02e2f5bc7742392311aa6d4897fb" },
                { "gl", "9aecf044cea210a0a23dd552ce309db704043c61e65d2a9e43d85601a60a7bf4954727bffc9fa9204919072568fcbeac46737cdf19aa0b7eb7d3d1ee64255b30" },
                { "gn", "a34bf65206fb16c33e54a100bab13e96673f06da091d31b387e1e10f3816a1d392469f6b50e868cc5cbd787b773e6ecb449fe243997afb19a725b2b8a883a2d9" },
                { "gu-IN", "9c0aca67060291858cad367790bb95f7b0f4e4fe34caa107b0dfcf4bc83475defdd4d596d65e13bd3b7fbb464d795f24b447f650cb3d7c8dde2a5ab7929539cf" },
                { "he", "fb9e5c78fba9d963d48bad92a760ca94c50ff0f5f4d05da655dd4a6340e4532e27348ec178ecc50c1a05764ef93dc3265c5be6bc0d6c91d8884cb84abc2a9693" },
                { "hi-IN", "79641bd80bde7f627689d6b02408787c345e0ddad22649523d3d1be99170dc52c392608ecbb96e816b86d925d64c6a9f86f3362073d6b2f4ddd1ee2c51155d3c" },
                { "hr", "48cf7277ddb230ecca486ed19031b60ab0847e750944b69bf319c8ed418a021e71b514ab6dae14644754bc66f8fe3caffc629917e2212b243746addc6eedd7fb" },
                { "hsb", "f3c74b8816056cf57bb02ba870fcfd3e1be9a2fdce5244da91806835d53d142f09cda679c1fdc0139cbd2b148909a6b46d4bb98392d344063233aaa2a400d2df" },
                { "hu", "d2d52a4518408f6b95857441c8040e966cfca377f932c2f313b01ac2f1be7346d0f1caa100963cfaf8cb4c6242e664ffdc44e2d9cbdaa5e9b320768da5819698" },
                { "hy-AM", "c3853fcb1515edced4953d2b7e11d646fe20fe4efc2b47f7fc812598cc9db02c4d2b14795c820c61d6fb5a566fbd6f3b06b4676850cfa31a505924756db3ea2f" },
                { "ia", "cc93c332cbaf975a370d786396164299e1d298ee52cd28b0c0611f996bc80e4437f4041a08774a9bd8cf7baadb4f3ac626eae8f29a490cf16741a1fc00d40c9c" },
                { "id", "ab2a9ee1721ffefd307ae58dddd8e4b5bc6065813922fedc3f7d5f29d79e52d2b3fbc83e6b22f1559cfc0e4f40f5bca22a4d3c1649de26aa0ae773c3fa4356c7" },
                { "is", "c9d3a29b98e66a85647b0fe9535555e7ccba124d7fe1b5d9022d67e0eb173114af79fd15760d15373b706cc579d215da9de6d2984f160edfbad90f8aea925618" },
                { "it", "30e86f8b6653754dbc8d22fce8f63cbb4a3ef83be39fc1da4bde3ad5b8bf75de7d702589b06278d36e091d02860b31350df03b56f26dc92d55424f47b241f36c" },
                { "ja", "c99f10d0a821ed3ecdff172046462e8237eb4f8395ca63c58eaef756e08877ddc03b292ce4440b08166c6bc7c64f7f23de19b46b95bfc8ccd106ce3ad44bbecb" },
                { "ka", "791ec848ef81f100c9679c4fc0424ba8067f8c25c282a57d0baaf346f0777dd7aacaf036a4eb1ccbabdcf0744344282b516b34fe184e81cd408dddc3578ca91b" },
                { "kab", "a8a466a246770af11a7e95100c1a7534e4c468cec69354be36f23488086e2788d3cffb0f144ded99a0ec2e8e58c559ec8ed728f17e9791bfeaaba5148fc50f2f" },
                { "kk", "b612488401d08a1ee1285903f2f2815af0508a5f33ab5040da15f074a470600e56341ce15f032a66fbecfe53d5d211ed349181f3e59c685bc3f8871cf5a04167" },
                { "km", "aeb8f8a5eb30e4e6fa947ccf1592ad36416ae83b370bd45454590b30c2db1c2a597765c0243689c381063e9e0640522953803fda0097a0b63af3804a7f08b92b" },
                { "kn", "04e7196ca1624e2126afb4bb37c025fc7fb2c826c6f118052ac7faad769e766c40cbf83c98490cdad8916f82cd8ff21c735cf52c76db3e26c9e15053d03c440a" },
                { "ko", "58db63818e12e4c181f86263d85c595dd3876dba31adbaf4a8fb160085e7dbdae6d67b5506e1140de4128ca260a0a3d5d55ceb11d31f493a7f2c95eff61f8824" },
                { "lij", "39cb0b180ad3716af1874f6136579525ef883ba020cadb06a738ae36a28214199f5e1ce39be0dceae7121f1ba11ae5c0a44a4cb45435c105f2275b66a415bf6a" },
                { "lt", "008d3a41ca318293f810c770cf54dcf259a94fcca2bbdea0ca9ff2c36f97a5c0a9261411eb684df27a2f0740e41fce227e6fffa72d5e1e176e812012608d0b40" },
                { "lv", "3ab029828324572b0237381f25d6d21b76e8c8696594f9ff5691ed5275234da4a5b184dd94dcd463049a48b56356cc5a0f84d8c3dbd06412e76139f95824dc8f" },
                { "mk", "f0da61719a5393afa048a127ccc6a8df351d8776f5c5675900bf49b873b3a12e867c446e905538a428677b77cd34cff195c7bba9792d0e42d4633c0ccdcb7a51" },
                { "mr", "3f282e30ea3b3a7fd2a865f76b4dde1d6fa7e325497c4491521afaba360a249d9afc9be20fb56c0dd0b2abb153e3087a4aa461fa5c6c0e691f2a57ca15d2fecd" },
                { "ms", "26811f2149450b6d147abfc704babb454c49e7dc242508e1b7e4feec86e2c6b1b4eb12382468b1894e12e8b19022cb56606cd91252a96a30236f32f92914a8de" },
                { "my", "8bc72d81b49dd43b1c94686508e9fa7c3b1737340392d61826dda7676b644d40973e68b651f67406438b0a33edde5f786a7a81413d1a036f08e012024306ce69" },
                { "nb-NO", "525bf4454b78509d23be9082eef8c54beb3c2fc855a3b7b91992bec390794498d935fed98231547383dbbd87b01c0a9906747ca91b672f3106f404f21fb279a4" },
                { "ne-NP", "1f784ea0394d736132cbfd9d62aad69daf57aa5d9b44403239b1d5e7488a05b6d3387673718da57d1440102547ce8ca60cd0dd515a0f4e47f8a0cf215b510df4" },
                { "nl", "4486e5f0247f9ef796aa293a3855501f464f76573e5e0d2c1aa3001bd8be0586a8bfc10959708f25f9b534f51c6562901507470606e6456889c0c1fd56d2f55a" },
                { "nn-NO", "7b01105995946f52ac040ec6cbc743de51f19256823389fd83eb6ad37ffef2492c2f967df360e35b2b0ae6fef3a5e4375bc827f50ccee5908647a014bedb30a0" },
                { "oc", "6b72e8c7a66f7f4dca7b10d9c44d5e558294f32028c7f6dbbf1758c468061958643b31cadf9d523d07003e368f8a3ce0e837f58d7f43b438cf3cb722093ef056" },
                { "pa-IN", "133da3df7ba3be76cea84e7a973fd5ccf6d2d253d8e6f51df037b7de9913b210ac5915a9f6eb522a5176716971be87a4b7a0435e1663b86e466df9c7709c635a" },
                { "pl", "17a02b3403bd1b10dbd6cdc0f1b2e6a31f8a570636bfd92b26050fff7d62666c8f2e1bd3bed86deac97b149a3adbdfd3ee8fdc27d20ec39d8c50041308bce31a" },
                { "pt-BR", "6483688bb503e6e4ab2c9e35413a23d9bbeb4f1bb92059c55fb0c1082a62ce6bb56cc69cf90d39bf00ba021c48fabdfa223d0e07b81bffd230132bd26ad57f00" },
                { "pt-PT", "b53a59ad77abe3b91e584ce5c90c8cc7b274a811644277df97221dd257e47398e56141b31181f35093e3ce0a220d5236d3f48061059d062076bba0100798f248" },
                { "rm", "c1dac2589604594f9cee6ab058d09e9e87ca8e2e55f84301548d97e041dd81903fa241eeda6da0f766f0c51af71d4e84e7af610da786442d0ada65a7d1fdaba8" },
                { "ro", "9bc80ef9b0ad4f593cad09f553167ee52d28bb1e282365327f81fda8ad4de8dfb7f5bf76f6a3bcc5ade6e9006b8ae8b560ec65ea63b93a2192e2c393df23d38e" },
                { "ru", "55db5f754e79bc027efa1328a9716f52a5d2dcd39fa3f81a9b1238b18836e7bf12f766e634be703aba22bb886db2319dbc3f98005b4883216039627bc51b6104" },
                { "sco", "cc0dd3565eacd7299eb121fd229cdf1a0cec9534b6ff16ce62399faa25edd1852fb52d02e699444059f8227d392b1984c1fe4c0137bf74d4a4be4772f29eb40a" },
                { "si", "9e359808cca677ae82d4051aa5fd88493d085cba00a56b75f8cd07269e44f8d894d7aa7cfea671ab4ae450c244e970c03968fa4b72ce39e5a4b905abbbc79d41" },
                { "sk", "592a30db283803d7051a370ebcefca2db6b8aca60aa1065bfe2e0b4b9fe2c929cba3e3dfdeaceb3d76f24dbd4de07c115b0bdd93e54ca22bbed3d077135cc93c" },
                { "sl", "ff1ac1a62d3195947e4ae5541ad9b5e4febc13da9289b46bd713aab4acdd6317239a2032caf52a3af5a3d50e0aa8611dda2adb6289fd4b962378c2125e2d9e1f" },
                { "son", "f122ad9ecffdb94b1ecec85f3eb91626df768fc3ff54937920ef7065f24febbe2c1c02d416c4954643cedc340510103a0406dd4b09696b2e00da08ed7c7cef06" },
                { "sq", "cb06b0558d793ee03cdc060d8f66cf6b7d64cc9e6c907de17dc0f24f71430ad61ff569e4c575f8c74fd00fec26838bc1402cfc37018d552bf4207603ca88a435" },
                { "sr", "263710cf444ac065d3bf2216da2030b58689ed78f7b6b8e0f7869db9ed2a847b1c88148c3987834003b409e97474b489a98bb0c63dd2251c6d8d943d289d744c" },
                { "sv-SE", "bd7e0c2ad8c5481c00f719e5218a37aa4929cad2d999c2be2cf5eb88c4646037dfd65777fce3ff95b2db5c2ce77667dc6ec1bd63a17619fa761a8392ab3156d5" },
                { "szl", "c982d6e9a06f9379f1578f8c2e45514651c35511564b3c0d85f356d799e21bdd4f52e79b91df5db6ac53bcf8e67d5ee87b7b0922b45e2b6aedae557e9a958098" },
                { "ta", "7b24ff0dafca52bdac2261b157627fb008fec170c5936583081910c740eeb1e1955927f0b7f6d88be4780a328c72389345500575dac66d2416716de43835056d" },
                { "te", "ad37749252fcac274d11819a9a261e88b1675d47c412443613561f735e761d5e66b59d8c53afd6ea6f412903beba16ed338ef9869842f244a19e70476efd7c36" },
                { "th", "a8fe25aa8957e5cc76d3fcad5ffc144f2d4a07125ff7e4ec625c3f95080dceee0299f87d2a6435ecaf0bd09c7078f229149b8b0426a1f7ca0a62dcf1894cd591" },
                { "tl", "256b5e1ae18b8bb8785bfc81d1f5607c6097ccbfe3f6dfa8db4f0dcbfa8db60f65323278f399f1acb24bd270d837f5c945a1ffae2d43f3ac5ef533a25f7b4785" },
                { "tr", "c6d4c19a605f6c070730efa508392aa57c6668a607b9d88901e836924d904cc625bf0c9b26e8dd7a09af9498b5955d10523597ac1e4d253a1091bc0ffc48c1b0" },
                { "trs", "42264f74288319cce2dd1638bd19d0f5885d57196c10cca1ebefda6264d5cf2d73160eb4f3fac031d2d003317a4c1e2b0fde8b1fd0a842b9a7632a82287ee748" },
                { "uk", "4209c87143d98d57a2bc69980ba293782a0601d8f7b0b34ead58aaa62511f92e411ccd234578f175208f0783807a3500127678a25090629c880ad793128dfe50" },
                { "ur", "7fd62051b93d83f0370334a26c63580dd9b5864e32f3a5f5a929c136de884d2e63aa759d85c4455ff4ab290452c0557d678034144e8246e150017da1d91c0fa4" },
                { "uz", "bcf889d6100d1a3f071acf37a722ab5e47301e981fa615159b0b9c61a9f716f6803ed7c77c6e2ae92640acb0aceddd312d929fc5be649bc7da187440736454c7" },
                { "vi", "a5936abd505014c2487671874abf94efacb58280cf604fe219eebbdc3779c6c0b071fc7db58e9ee3f1a224ec47fec31e9dfdab4170ae4499110f83079eded4d4" },
                { "xh", "2bf457fa997c251233fa9b4f1e2cd423c46ebf93f623edced9207fac2ea83c7e651ff21f54a0b2756107dd3db25e73f27c359b3b78eeb09032857c2d14b1f4bb" },
                { "zh-CN", "d482af199ba63f839697a8631bd4c91a09e8f9f759e086b3ce42e1419987b34f41db1ba4fc3b4b02ef1110f31bd34b073494f89cbd0e65fc0128f22bce245fcd" },
                { "zh-TW", "284016481dd1bcf8cc33ba078f5d7855a7f6098199dcab21b894155cbb523e0d288c2cd545f29c7d3cd2f302bc3e87351f2795d813fef85918bdfe8fda7eea26" }
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
            var signature = new Signature(publisherX509, certificateExpiration);
            const string knownVersion = "91.7.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
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
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // fallback to known information
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
