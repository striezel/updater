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
            // https://ftp.mozilla.org/pub/firefox/releases/117.0/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "f7f5af8ae8b50c1c6c50c48aa8b3196c21d19a6c8347f509baaeaeea072c345340bf14df8cb163409d6a524624793d8ef957817ab89a1478bd41a86e916621ac" },
                { "af", "68f1951ae978152c5f3ee316ccfc1e804ba48734df37b63dac3d638b8a3e92b5130f16efb2f7e9858882a82440dd92b0cd8c34a5abc480b9adc6964a77114d36" },
                { "an", "72accda38fa0783949e77269f5a537cfa7ca8f0f0b54b7a04fb4e506a75a41d1c9aea52c344520969b497873575fa823287aefb8f99d539c01fe93e3d3814e9c" },
                { "ar", "e3323bc52af959e2b8b9473e7a36d1d1234b333d523a03e37b20977fd95e5956868af80fbc5d0c47bc0fee5cf9c04abb812bd602cff8c5f9983deeb7a11cc696" },
                { "ast", "4670b722525d59d1eec7e636236184fc1b2c1feb295d07bff980a3f347dbfec6e5600f95fc3a5cfb92e0475a8a6b43e8dff41e03ac39d08dbe177db2b04b2966" },
                { "az", "e1a6d353a35a7863ca533e516aea2d673b85a451bb5c401816af7b173670d23c795dc51f613e1fd9b7bdb04b4700e77cec52180a123faaa1b8e0a025fb7ceabc" },
                { "be", "fa621b96c7b83e88b5ddc4e15326ce79fd7f9380ae5a504714d685d35647db040a76030530c51325c8da336cae9e879f23e1c6f9f9b7d8547e1dc37721b1db81" },
                { "bg", "1a5a91b385aa5b95c0fcae1d3a59e810a08738846bc039e5f4819e762bafab7242c7bcddb5d8bb8dd7d5222e9684819fd741e87ae443ada22a37e1728323a5d6" },
                { "bn", "ac9334656314d3c16e80242e548851e1177ac1c0bc883eab8d4d1ef6d5c21a6bdff4386c6e4636ce1782851ab3e4e7c9454acd0ebf11a9e074890fcebc4ee9e5" },
                { "br", "eda825d61aa2c7e3ca65adace343476358ab00124631291906ea63ce2b362dde0d83a1b216617006f2654602da3e7742fa90eb007f90998d59a8922af0aa3d57" },
                { "bs", "d91a432ba238d180ec947abc5017b39e135b0823d4c68049515e1ba5bfbe352481a0b3da73db1eedfb5ac94d84286419a6b7503ac2b984a0e2b5ac1025c82710" },
                { "ca", "d9ffded9c5a805a00dd61853b0c9812f7c5a9e6170c5680e58bf72fb457ce03df24119aeebcc6ddf8fbb182481a637c3383ebd10673e81a8ac276c8265c227e1" },
                { "cak", "2b801a35b8d0c3ca19d05173f8b54f72831b7bd8471dcf33f2f4eda83adb2bf2b67b8365c35dc7d9bd4569c4e6252913feec1d76ef5d84342ef2c770037d7100" },
                { "cs", "e42bf1c567741535a37135704106f021a3927bae8a25016e5273e0303cdc8fbceae618e5bb28e4e0bb43a9b43321a9e39d65defd93621b1c022ada376c63b69b" },
                { "cy", "ff8479441bbb5c272802b72c4ccf55e7a69f848b66c83cb8dee0f9b32096b1b8d03dd561559b6e0cfb1055585178034ae168eba8de7588138086dc23c0868ecd" },
                { "da", "8aed03553ceac8e31c32fb3d8186cad7157277d967a2293060a82c5eff043407b67801253e63f5c20985ad7f8554e1ff3be24f09901c6707037d000747976bd6" },
                { "de", "c973cc144f5829e79aea7952f7b80dfd89977b9dc8526f998a832b12c17bde3025901d41989549871c212369537a5efc960efecc5835d1c730222d67959167d0" },
                { "dsb", "76c9dd579244c3391de2349706d2769a666e1fff22f3f00e68847b9b9d285f6aa1978c4d24aebd032fb5d120e2351b2ab6326c08bfa8fb7024b7d27f2ca29923" },
                { "el", "8d5ed3561c4308313677fc1cb0c51dc7ff27db35f423564d249016c0e9aad2a96451bc2c964390eb0472285af236d6f1fbb57388c1b61cf30f23e6add6774cc4" },
                { "en-CA", "864e8be5929b33b0700080c2eb5ad62d7fa5228aa34cfc8ab3afc65596845cc77897d65e86993a1b63298f97d2e2b1eb16a98f9018515171f481734eb5cdadc2" },
                { "en-GB", "6f57b726f5fc36abdb2b63ee38ca90285e8177f975344407ed03ac5fbb02ba3b0217c53cf7d29f1d091e456c165f5ef83a8bb6175aa58620a6103742667b4525" },
                { "en-US", "6ad8d8439218b9e92df5ee04af20c0d2fab54d0cfab9c6da0e8f8870842f531fafe2d764c84f3a29751a7224e259d985ed0dbb7798aa960d80ce8d6a4ba243a5" },
                { "eo", "f64c630299b397523bf16f803adf4c3ee658956e4072d61a208a93baf6aec0836276a7de01ed66208554725fa01b70b88cfaa487acbae0ffe1e59bdccc02c52f" },
                { "es-AR", "d527dcf9bdf7a7c7656cf34aba9b85090391db13a6074d91a1065d6c340a812ee6dfe6abf0f4f33589ee0c4c71e573255790798b30faaefc8dee6c496adf3540" },
                { "es-CL", "1c4d53d459b5e385f042d669d8a5023af09affc136640d1e48c6527b8bdbf48428bb1f2b724105683cfb5f35252b29026d9b950155131a7e09b49ff903e0f24d" },
                { "es-ES", "1041e28a1779e4c64581b6b67e81261518e8b61242ef1679f57be06187499bb8220118a98bbf2bc1c8fd1f63c0d9a1d3b0481f499df0637b1725edf095cd7b11" },
                { "es-MX", "579529ca1bbf77fc092a32f2b7bc99c4ac3defb641de52f0e4270918b784c8599568ca77e557b5e482e8ee358c18855662baa892c747323bf5ce6ccf3338aa03" },
                { "et", "e7cecc72b27330ef920203260b5f34a1060dbe9de759f52a08047e3047cc9195a6cce6d9d70aa10c8047b17010a91aebd2cba0235ef4b12431f9a7e7af19d0d5" },
                { "eu", "e408f297a3bfb22afd49125fd1a912fa8101cda0ef180f19390d95dbaef6d58ecedc6d72dc2ae955473a871b87215b9754d612c481ad2b77ffa81e2a8e36c4ab" },
                { "fa", "c6075564627d25967f6736b402375a578f76bdaee8d392a437def76611bc3e218eecb8b4f6240bfe58877021f0b1418601af5875c92f542c0c51eae5de063246" },
                { "ff", "14bb7559109c51a3c85c671841b97754aa6287770b8290ecae0ab4b369e4dea1fc25f8ee903ea0cef8c1fa539ba124dc2abf7fc2b4a303396ec3cda5e4225c6e" },
                { "fi", "9eb983310d1b6520fd019e07ec5272f852f5dd4d2ab2f66bdf5dfc01d401d5a7e4740717643a8424bc3693b8e1f601360d2a9d083c1b982e7b4a645335bba8ed" },
                { "fr", "42a4e5e7354f38d189651d032cf98197488c1b00a578e0078aa2ae943bf217c3bb03c501ddd6e525b8136d8059be7317b3b4bc648b6d550af1e904fcb0d4f58c" },
                { "fur", "9ffa933bb8b2d4318d422f08493061174a3e5b3710ac786b2712af3d6fdb36cb76f895a599a8e1be360efe15b243e652d34f864122f430924c87d2c7bf29a903" },
                { "fy-NL", "ca5caf500852e9aa7923688a59b814ace28e07b121b934f70ce1dd6c0ed2dfe483d8d66e2b9d79979a61ed3424d5d427fc8db011e564ea129624e83af5e6cf9a" },
                { "ga-IE", "3bb5c9876824bc47e7637079b9d7b75948e3b0bd3f3055790ef23e71a73942281f39729788caee6a4f5e72a25e0840eed76dce422314353add46c6d147b52872" },
                { "gd", "a44f660fd33df9c33677c802478580925b84550d189362ef14ba88badea5666561aa2829a3fe6e13caf68e30e392efdc7a37493b49157c5748b9ef754cf61353" },
                { "gl", "de7f2109b6d45d2b918cce020bd8cb1a583b5fcf35423b5984762950b350500861058065f28789c046b3cae4928c09bc71fafb1cafd25b6e6a94bae1fe2ca531" },
                { "gn", "5b9aff42d1e712ef1a21b70568a80cf83b673478fce71f826745011ae058b153c01fc0d4d8282121f77601d41ebc59751bea44423027d48a59d340d045e7f361" },
                { "gu-IN", "52b4033f03dd82bfc315cf15f5a660c83f8b9eb430bb310584aab7141a1cef5ce3d3b0b77f04574220c7ce394f9bce508906744b16f1b936c67d00856500c3d4" },
                { "he", "c6c537284e09246b7c7921de9d9c3f59cf634436d0f81be94df01d2eb4108483ddf6a4ab13eb4a11ff060c6951e60c0a2b6fe1edd1dd0f8f56c21bbe6131a571" },
                { "hi-IN", "02f7603c40136427884fb79766399ca5828471e3356dccaa03edb50ebd6e2df127f39d99a08b33915f795b6ab056be9b98a888a2f5a00ad41416b10094474632" },
                { "hr", "14942ef7d9a4f840a7b98e5052fa87ce392f0ab46404122eed82610ccb8c7b6c9863fba080bd7198126b36e4c62574edd6405f35aa5339f8454e6a29809bf713" },
                { "hsb", "e6a501daf11896050cb04e0f1f1bfa337123cb40c3024e58c1860594ad820b521622b4ef26645cd26fa07a31ffd515fca5c9faf54cdf3bf01b6136162e14639d" },
                { "hu", "4d5b83d600e29b602c51efb03ae569b190d0aa3bda298c790fbaa1ec0ed22690c9e2ed70107f2aec589429f1d153fc1a62d80dcb41c343a3cb4dd424fd4ce1ec" },
                { "hy-AM", "e7d58624c684aba9b8352ebec5af8a5ae5b48ff08bbac2f2cbe5f5308f4442d0302acc2cf6a05b9f2b8b34596c851aa247c93c152aff7f7a1d6059e958bb8e2b" },
                { "ia", "ad7585e5cb0a8e35b905851824c4a92a283bace7e9d9cc91fa8ddd056391e83e66ceb184099b6d0f82c22d847fc92424b29892763c0e767078f3126ccdcbd59a" },
                { "id", "f53b4dec47776a003760336bc4d04b0e3b19d3ab84eead12581e2a12e5c218359f19a236238a10beb3701b350d2082724c25293510830672b09f1b192ec4a565" },
                { "is", "592970871ad85b47f95754fb995b854015e6a97116eccff31b7fb1310d287a051be8fe0497b46367a5a12260385fca1284b06d1a719ecf06868fe77530d5fd53" },
                { "it", "a0499db3d3f2890180ace5356b2b94e9d9cd907e6eb58bb4230de92c342c1c995202c1cc3ceba793e9ac20a88921669f9a20a6375e4ef15cc7cf803aefe3633b" },
                { "ja", "93ba6ff30385389518389c7e883c143f6116abf242da76416a6fc87c63d37abe7452cc35a883d80bb2b96a0d2ba9f5396d4ab32cf3a9a5cc0791fb9e918e70f5" },
                { "ka", "a7addbc8650f52f29aee610dcc2b817005c072166067215c88cd59d8fb99b2474cc9e2300afcf5d425264b6bf8382b428537fa1dfa9303c3ae33c4c9d34e99e0" },
                { "kab", "b79c96913ae6d043650237885e82120c2d5a96e0225f396ad61c0aeffa33d3b4967be63307f95f62a5d44e1212d740bbf5140fc09554d0416c2e4ab1b619e36b" },
                { "kk", "99aeb20c911f3db1390744ab5cb9311351568a807a2320764ebdc5e9e09610e41e7ac0e8dec5cc9280107b2cc28fac8f95740654feeaa9055bf84368d77d87a8" },
                { "km", "15515858831c6ebf91c1d84acda22963b2148b4135e77e5745d896aa3a95505c735b0aaf885cc2465c15703587a5f484dad664bba4dd413761a8f8a8dcbddd9c" },
                { "kn", "538409313acafbd2d46d83cb3657e85f1163669c10f232e876ce94c7e908789cc6fe6aaacfc14413996b8807a1d686c35cfed7c3810b9405b2e21ed40c1f3148" },
                { "ko", "0d9b46bd7dbad0b973c3a3fa824afa5e3cb5bcfb32a2b4b93de246037973381990b6faeab49c39294c47c84fd252447ca73a2e7441d3577e13aade1579d1734c" },
                { "lij", "e1df7d15ec4224935efb881a296860596a7c420801414d02ecc68833ea9c1ce09ec45ad2a8f6f6abddbd943460d27cdcbd0a5b64984cb811b5114b10e0b16c59" },
                { "lt", "01901ed57b0a44f9a7c7ac204326c67fae10373d7c613ec67110abe564f28e9be9b23a6f4f01eb565554ea37268f1989b742908da36bed07116e75f3862da13d" },
                { "lv", "982d448d35ccf6c6fec1501feb10b4b2f382f511c6fbcf53df57d4c2c37a15eab484cf56a38621de6c435d0b9e39c7f29d8151aa396c873ca67332d640d9e4b2" },
                { "mk", "8b54094050a165130c0ce391e44894131a35c0173f0da94567ad75fd7f6486a9663cd3796dbc34752addc7146cee49825419d123e1caf358bdfd358e02f8609f" },
                { "mr", "c3b297bc359776b2df7aca97eea5ce49b591442941985b97d1f46e8d671a4801ceb5fd3087ebbea21fc2e4445dcaf463401c641bd23ab26a47acbb28af98a730" },
                { "ms", "300a43bcff9c5271912163755f24a3ca21a7b979e745623db14458360c70370b8509d60559e08fe6dcd876166c8a8dc70da1053d8278881649b8efd5a0d0fc0d" },
                { "my", "c1fdb2df185218ba1dbebcd777eee509d13a71c0e096cd085eb0db9e65643f155779bf8b0831aa69b878e781cb97dd4744b59acd0abcfbf4e53f78c50877d49b" },
                { "nb-NO", "4720f9a519e591c7fafe06388fd1eebbb66bd7e5576f9000d1736941c9d19c360c2a3b4b2cf8f18e1dd3e728b53d43a976ed2d70bffb7232fcdc6562ca0fcda4" },
                { "ne-NP", "d6254fdcd33d053311e48fe5526609e79cd0793c65e360a551cde215ff76222242755e1256083481f063270181736464db2ec83852d2f3154dbeec33ee18dc93" },
                { "nl", "8692b1bf06ad008ceb09ed0811782646cd746b74aa5a7820c01c85f56f97e7711e62815d7c9983c27994013b58df98243bd50b4c4fa24033874a79ae826c52ae" },
                { "nn-NO", "a97e50ed1023ce7ae10adb4440b86d0cf408e6df60ee309def19b53a587975a1df6ad2efae678a47421c41e97c50fe93eeef16f4c0eadee493148054f41e0c07" },
                { "oc", "20b3dbac61b91e3081e849b65d723912b6796b3b68f221b212266b71ee79f817909db23584b7cabcadc4b397c704346131470c76eedd10f89507cf291758c0b7" },
                { "pa-IN", "7c03dd7de87c2769696016e8826d6ec92f42133e5d81b98c9f6ca8e156d28cf20ae3e4b8d84d9971307c9b9df55b05e4b1ba1df9e6e1b41c83320463491e5428" },
                { "pl", "4273e8ed295e6c5f26b950271e90b8421cd4d8c480f13fd1e0d39743e53ab050954c0639b6335864634d63756d5d10b0c00f446f7028d24372f320c79443d927" },
                { "pt-BR", "2de2dd02ce0d6efa9794e9c5565dcd23616f6d070ed44c9ef1697468955f343bc218ca62e93ffe0cdd1653ea00ebd8d5e48c33e8696f06274fd807f0db3e3fa1" },
                { "pt-PT", "6454e269abf98b4eccc19b106d67128e8d106560e2516d454299f5049e28e862a3048142d39c953e70d6b8b1d3e9c478f47d7f30ce5204bbe411517e7d8000d5" },
                { "rm", "18172bca88849eaa525f76ed75a0cb9bd39b31f424923354c7fd7541d042d97d9b4cc7374a902f516804facfc38bd0c3bc112f045e308c7c17352696ebf735b2" },
                { "ro", "72c2d0ba4beb52f12e6966bbde39f198f51a9c6dc9a226dfdfb62d7cc74549dfa495cf9690eb3a0da1a036bfeecd204454ed3bc60679bde92a86a00b5e0aeb10" },
                { "ru", "34722ce361b5e79b47ae424ddb6192fd4627d36781632697397f1c2a57c9db0045321d85213cc9b8be3e5abab5fa26973cfb4694fef833637f716a5b4e80890b" },
                { "sc", "053058bea44f85d2d83e96ee705776f99f8843c9d185b3e3a92c81ea3af9f22b3452fe680d302611a29ce6595977f5a0476fa6d27203589ee24d405a9e71f34e" },
                { "sco", "070f5ea8c6b72835f08a60130933b234ef5a0cc86637d41698c15f32ee55f4adb88fb7c20c07726c6844d589ea195c67ee9926802c33dc26bf7706a6017b179b" },
                { "si", "e01bcf50260c20ca0513587a8317d1332787eca707e350d8490922a8116ca2d822649137d4185071a7a2d9bf66a816fc388e607fd03c5a95d227e4cdac1eef6e" },
                { "sk", "e5b137172d1a5ab90a614b07f4e58556ca27654bb398b45f7177708c0b269d3447f24df599b01d1b891edc02e51bc933bd77494fea0e137e673b3326d1190bc7" },
                { "sl", "0e47abd6a379c30f7f8af17df2352ca3526e56fd5c41738f74ac4d2f0759e0f6061af84e7edecfe03fa92b6a14feed948a93cb5e8eb68dff62bdaa3f2249a331" },
                { "son", "57c7cabba2c6572ae2f06edd3de3bf6fce3fd8b94913e09f890dfe5dfaa1fcfdcbce96c0849cc6c4ecc076355b57ddf5f65aaeb02ec6b312c21275cf9cf63ba7" },
                { "sq", "ada5e6024cc5b9be94441e78c104f29a0364352b2a638d1cbce627be13b4312c088ccb66354e6772b004da361212a7e9e0ea1f31ed7cac898eb6d9f9cb1876e5" },
                { "sr", "1a08f4bd4e3603927f01793afd253f7c02ec156046c178649f36af7ef0da8cbd9d768ad4168ec81ca675756cb971f6454831490b5a211345db314667e9716843" },
                { "sv-SE", "3cef6ddb66190f07c79eb82fb50ddb898ce7ab164ed0bbd7b85b39fb0398c373d2822aa18bd7eee60fb8ad24cb4755f99724cd64cad1f839d26e7c7328bce2e9" },
                { "szl", "635455cc73a515f2d72a70d49f75ba0e4a62ffb7c67775e2042525a42b7eb6b691597dbcee6056f7e85c80d1264dd4e1a0ada96ab2e37bce6cffef4c4850b587" },
                { "ta", "48c898df991c984ca86ce40ef95e24f2e3bea869ddec1a74c7403449269c8f7a7af48272818035a1d93b9dca30a3f4118c6c64517a302b83a086f340ab5e2e4f" },
                { "te", "7e8b9322e3993bb5ea98a7c66f14d1b7431e5ab47e21554a126fdf3fed4a2561da00183855d71386a2e86bae0ce3fd34e53b9ca2380ac7b242abc262dea26044" },
                { "tg", "92adc8bf191db422ed696716609b556a0c06912db43cea07496557532ca1d1ccdbb2c5ecd1e53b1a465b320491741d8dd5175cceefcd8149fa71c36aaf2376c7" },
                { "th", "59ed68722033c8a284275b50fe3d4e97398af2fe9c83b8ec200860d68e30c29a52f119062acc2e2512ef0d1b7682f8bd67f916115d7219993ddad9f4ba241d70" },
                { "tl", "9c979c533a7c7c36e31013314c8e4a569c2419d5ea25cd869e904906f9fdb8bf617cec69b7b17a9cc35b2bf0d634b62b6ce66871d6295c4d8c9503278d00d92f" },
                { "tr", "9d651e9823f7f4eb134450b5071d9223b01c6697ea66cf73c8398706ab267eb9921bbef4757e102b732c8242a6cba539603e7591c9a52fc3525fb4f0aad370f5" },
                { "trs", "7015057d6bedf62052d98bb5c66269faeeef709832b996343f16012d975a322fd9f01a4dffe3fcda51732911c312d4bc7f852abbfd2433f796b5877167a6eccc" },
                { "uk", "85da746b1989419f22fd8d90079376133172fd4eda1eef3f444addb9a2f9861ee4f6a436edb81caa4d555e0160a8187c71ebfa86c1b3ec5eefa9b0661d885fdd" },
                { "ur", "c84aba5655ed49aa556e9a04c38b0173811cd9d9218e31c96d2b758ff12fd82c361ce8a3783050dbf6a67de96d4112e3b0d27d29c6d0df8d5729304e364d63c2" },
                { "uz", "920d82a8c1d16276f5338d99d8e996c155ac5bea88aff8d83056d3cc98a26425855b47193df214e73dc7853b0f46285efbdbd6c9b2294a8ee05d7ba3d3548ca1" },
                { "vi", "5da04dcaec79e5b8aa13a2899783991f07e6cbec6b45d24821480a048a8447de50e0ee5fdf0785e50c3c9cb79ec6f7aad5ad4c3815da8f8f1f4cbdc33abf1f3a" },
                { "xh", "51cf60062d08ff5c188bbcf49602127589fc69ac3f7672c492a5f98a7b0923275fef3a6da69744c538b9616c0b0b39fa5902556a134a824a746245df7cc9c95a" },
                { "zh-CN", "54e53f36e61a8010cac34ebdd6066649b3449cabadf523124b2176d718362b8b00ea843ce859ad8684bd735d9ddfd386e2c8600d62bd2898f39519a8143dcb08" },
                { "zh-TW", "50b4e26aa6a08866e91fad8f967c962512bcafbc9addbfc8659d12e62cef25cc4a828662c4b48339cf8db296792aff0e54878410d067e17afaa88e8949deee3b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/117.0/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "2eda263945d53f84ddb1e19e2062c85607dde933b65125c4411b98169bfe6a31bb5afcbf47932983f641d4f94ba6f3ec3ad5e6051c5a74ab869d87f2d1a57e92" },
                { "af", "b6b2b4efcafd0702031cb1f075d9af30907f057c820903b48163beafaa1a7ca88587d1fd5b8ceda5cf8fb0613b0a239bc45f096536055f8763c90bff4249e908" },
                { "an", "701f0b518b2d3a5925504b13976e16ed72ad8ee4d6f8cd43453286d5333c81d0790ea165ab41565dd48911dd67e6140dff63da8c38d941065b1062937a35d90e" },
                { "ar", "0ee04296a3bade9cc61c4be4035289be4e106f4ad7f9abe0ceaed9240a5c57fb8648a8c8ce55c56d6f7c533c5ac4accbcbfc42c9bac21c5a8f522856c7686229" },
                { "ast", "1d0abd24201e228d3735841b86a0da6f00644d2be235ebe692ac62142edec896b647481c83ff3347e020d31e278c1c1d7580ef02361ef24d8ad5a6e9fe0ef6f4" },
                { "az", "99a0ef94f729ac898b16a4bcdb0306d6d7a7146ddb0f4235267cc174e06b601ff19231f267a5ae9eb40f39c341745c09e4524fab197d83f98b316c0931b55184" },
                { "be", "e0206153e8d26698ab5c6b7f27a8c8e42c782b68ca35c948e6325fc5709c01b40d54d609df8856a856a9a8c6d77a73ad762eca96a88acc7e27bec5678a5b1e73" },
                { "bg", "f45802a4c5cac8370f1a6e7ed4815d896cc951a39f4f3bcc0af77b8a76538721275bacc688de45ac4a1b3871a1a1bccf10ede1cb4de96fd24dd28733a216d2be" },
                { "bn", "2ea0ac3bb1ffe9bab9176246984a466f45df0c3c3b662b8d17a68e1dd943066abf75ae5109d3cbc3d1a00078883a232b8d806a93691d1eb1e8fadde80f92401e" },
                { "br", "ee364cab0545cfee4960c46e43fe468a8031bc1e6ceb1fd33f0e0a2d8f8afe4b3458627942d9271bf854849f5f9b6e1e481aafe3e0e896f158512a858186d919" },
                { "bs", "a2950e4db2f5f7dffa569cbf38546ebd6cfb45321e9c12d33194c40d4ca8f6d5c5c18969ca455027edf31962f97e8a4654426f4de94613683ffe3d2838a0c765" },
                { "ca", "18844aa1a266c53f84833edc8001cd4f8e4a0c3c5e28545a77b3fb19926f3a079eb1d19eb881e02667cdbda258693ed8d264fd1d72232b89c81b7e8670a7c35e" },
                { "cak", "75cde0c1f36443b6e775c9bf12a6d08bc388c3b440689e2029e7bc612ddc3b9bede18fe0b91dcce22f575fe4804b7e0404213a93da5e8357b43f195a7acfa7b5" },
                { "cs", "c81bd34536cdaadeb3cb97f167b9d71ae5d7862b901edbb96ef73d373c411a3c6c7fd43868e644a45a581fe5649ae7f701c7bf1db7f8c480e381a200fdbda1d5" },
                { "cy", "e2b161b96e5035850ed9094d6847c675c6bfa4327ddb208b359ec1add5c43292de171478b2b659ee7cf8ac35347b97032b2177e02b3eefcbd58f14382b611165" },
                { "da", "be1d35c5760e1930399023c9d49cddec21b7357170b411748de6bb56b6a062077bdd3cf9622fbbbd7381d76ef218c4716103fa17fc40c0cfad080b4860b9ba01" },
                { "de", "a673abee489147db711ee95c2396daa4102914eeb87bbcf0b07f302ccd62d824fa738c18fe461e277547e52b9ddedeb5990eccba2d76793e9f719a1c416ffc99" },
                { "dsb", "468a7302b9a78f94475f02690524ab86bd85530080c3b1875e3edce5755b994f5369966f94fb4baef5fcd17db7bb69a112e40f5fdde863a921c08db473446bd9" },
                { "el", "9c347d46a26f304b1bd88fee9e666c018041979c5a1fc0de0e4ed7c8e6d1a346d14ca957837575bdb87d91c5d98c922173b74ad4edc2c3fc05d9ac80707e0106" },
                { "en-CA", "d637b2d84deaab3186e9bbde3f79b031d651d123a302e9140c9fc450612b035f405020266d5e4b8e8f55a64e6d622c6ed057bf22f23ccc81f6d0a0c10ee06359" },
                { "en-GB", "f54249059d0d125766d8e335507535d9876d4b6517a6c9efaea5b4f121fea5f3c8f5671b8c3cb7c9df1b1defd7f075a5cdd9b8460f26818bdaff12804c949d24" },
                { "en-US", "1069638a725918bd7b568a0190ed1964f641136a6143baef748db704117afa2e037b13c5f6194a1874ff9b3d107dc06d54e86caa974b13d31e8dea06af7169ed" },
                { "eo", "1f479ca19555b3ce1014a61b90ec19ff569ea1ba99e4dd985222aa919cd3e53ab0cc3f51379b3555120b01a33495b24d6577678847e6a97568f81521ede6857c" },
                { "es-AR", "c0cba0bf99a7a01b6da233ba49ff3a2fb74dc74e4d5ba8b500b603dc36143abd345a43e6f6d0e6f3f22379030177c75f1348571f5a977a8682f84757dd6ad0f1" },
                { "es-CL", "9b2741e31bdc55ea6d24fdc16003ff8accac751fa8bd82ce33c6b0f3e48fb54f929c7cb011a29c533bce041ed465497703ba8bb3c2f872a4a7b5dbbf311de463" },
                { "es-ES", "cf1b1c17e42ee0905ef25f3bbb433a6d1817762993423ddc81d794f5315a773fa542746afb8672a6f59b0191c10c47af3a5755fefebbc56ece48968277295793" },
                { "es-MX", "11e5fc650c44fc1f4651f9c7cfcca55a57fa16f94a40ab7343909b818dd9e2fe57350a82d15b608d38f29e569930e076d09be647177d322d7a502cb8dc6fc38e" },
                { "et", "b7ef6395fbd9e6ef6ad915baf27f732781cc8557980a72c8402f6b6c0c9b5436f0ace8083502dcb189930c4e84b4237437ac78320edc0c8c7ec6330770b3ad48" },
                { "eu", "9adba6ee4e195dbe33e8f8dc8b1f480d491f2a5713c8e70cb2cad734ebb42a97ee7f01162a8d367e880aba9ef13b22b63340ab51ec95147e7a02d318e37843ee" },
                { "fa", "7c95ae3ccd74f6c30a096a76c71bc6a6f9434799693cfc5182f09d033b7d56a2950efef8128879638defa6fdd83d6749b7ad03128b6c0ba371fad151373fe6c1" },
                { "ff", "7fbd9202a5aacf0ad9c8b5c3c26a80b02114853b41adc51e7ebab9f6dc67fe2eae12e9a7758138d8b85d3227ae24ee54b86663d7d876543c18ec20be53478c9c" },
                { "fi", "4c14eda5a68604136136e34fb03e5154cf3fecd34892142782512ffb9487cb4537e3bfe3bcb4cdc9d89c6bf03bfe305f4a33b6244ef2f73aa3b281f4baea6fec" },
                { "fr", "01e0b5c4eb32f6685178cd1900972ccbfd591a57e3c1c59133c3925192925e4c84b292c1d4542d7a39be5f3ea5e9b7f92ad4a97899eb281cb10061f0cbe91ccf" },
                { "fur", "44a03271caca51ac2f348a2304e460a195f70b4c39b108bfd430fce1133698d00f22068ad018c95b561ffee1518cd675362609b682e9f63a970daafed7825bba" },
                { "fy-NL", "7568fc652237dd7cbab80d004e51903fae63b35c59289cc31f8adfe0ee17f9ae38871f865080f55b3667ec6e9160c99c3c86f6945a5da8046696a9bc8dae01ef" },
                { "ga-IE", "96957c21b5ede6e7fddbc496330b98e33b76a3a9821bd5d0751ab6520c6f0794052d0a267462332b7753eed93ec5d7f156bf4670aafba52468c6f5db4386d399" },
                { "gd", "b936c494f636eaf871f1dcc2a8b33cc714e640e414faf1b8459539dab5b8881801f281ff9c6c8c71f1f3d3c626fa9e89a4a7bb00bd46ea4011bb8d6c95ce83e1" },
                { "gl", "d3a07de999d70d3eae7ca4718b646dc645bf81800de81ca5161d2f25cd94de162bca79fb49d353302f7ec192327897c58b82a2969031029e3e2b6d94fd2b8d86" },
                { "gn", "9cb944138910ea6f58580721ffaa56d91603bd26dbd9b7e4505d7d4125e13244ec1c920993f739388ec2860dcc598799391581ea0c31bad8a6538f2b34a987cd" },
                { "gu-IN", "259964115762a01e51c8b981872e2c1ee5d746710961d9b52c98c8dda24940d623d318f6db1c60c93fbbc833d94254d5ba0dd863af5e644cc9f9266851b94c0a" },
                { "he", "45f624cd361a98cd2cc0ae388d48e79ca7c17e2666956a61aee89b2ff6c5ec51a6368daeeebdf3bda302406ce057ad8d2b7fbfab0a2082bf291b55407e789864" },
                { "hi-IN", "a03e58394d377943ed3c599c2b9613b4ec4cd78daf0aed07f5f44d3e0686e57dc1b0f05a49d2e7825be84af1c175cdc0959b145f7839dcbd05d1ff34f5d8b37a" },
                { "hr", "6efaf68042cfe28beafa92116e2a50b87300c7227d9759a496192d1bbea39de6d83433c5d53a127a32f64bad7fe37dfc4eb3eea7da65167a54859e578be703a0" },
                { "hsb", "1863819bc426f9c5cbd921cf9975ee9fda75760cd90ac47bf51b0015e665f7c8ff7e822a8134985b256d703a4086264cdc76c9a61d4d59b8c33b739b3c256680" },
                { "hu", "d24bbbd9195049367ee873000790cef1bce62243108565f16fce96decf480e23f28b3696c78d6030d63bd02b17a2d7d4a62f3a5c95488849b5677860ac4a2dcf" },
                { "hy-AM", "a919ec7baf03a5a054af2cdb84cd61723754e477adbbd840bcb50e9c9d23188114dd0eb41e800c1c714776ca1e3650e5f2b47237c9d02c89e7b0fe8b2bd1ae41" },
                { "ia", "3e9b984a4352ca4a0d5254bf00f86e53d0dddb19a8f304af59c06c802b1582723fa3c28302b48a3b947a8fe51adde88dd1cdf82731372f3b4fec558d65b6843c" },
                { "id", "26ed71c30ed594a99760a6379db85be73162e8c91d4a4a1d3c31ecc7d89b6c66cb1a3e4779ec5ea0fc1f7a71e66c488f16b9d5ab6bc33aa565b84b70919ac39f" },
                { "is", "8ff283c2b6f0592707a64bebb9aa9764d65d724dc67dc64a2f6ab1bfe55c83a771ff8e2ce22068a8506e904ddcf323ae7961a1d40f60087f6a14196e1ea2db51" },
                { "it", "68971cb5009cf559c42af53dc8a92c0022661aaf6904619955591db610dc99013a03b26170c4ec928ff234ba940a2ad5e1fdbfa4979d2f64f0158363e38f7c30" },
                { "ja", "51f104e316f30cdf1c3072f6d4d9a899cc1c9368dfa8274c04a45fc4f3cdf78bfa2e97f09558519e4b9c7e659328ffa4617c24405b0f0fcbd5709d0f7d807d80" },
                { "ka", "46391d586d071de8163d21076454e30111e093a9bcfb92b8e2c9ab25ae1ef93f38461deb11395115a7c5a03dcae550e8765c8c4c74b3a6b2cffe25a0413398cb" },
                { "kab", "02f7a7d37b7781499e8320ce6c90393ae9e3d5d2e9f8675c5e485190924bc6566c7ab32ef1315bd9456358237fc7bcf8c02315da760be0340cd797b552e82e98" },
                { "kk", "74788df0d925ef6107087e4b5a9f9135f3c9fd85bbffa795f902166dc3a1e94ec97f1df803d6f3374adcdbcd3d8bd6a0da159c2bbed1530e52c1981456b3c58f" },
                { "km", "98b2701b413ed68dc808ca3130b41ea077218f088f2983163efef98734d6d892f09e56a263bdc4c9a118fdfec5d97e17cc8b24d850b0dcd2605866ff3cd60d45" },
                { "kn", "2008e8d6af44031a40ff851fad172877788d9834426c1f883ff4696e3c5028cae74b55851a0c0dcbaa4435d12f4636439a752ac44ad541573d0d863000f9d20e" },
                { "ko", "3c0c03c60319877216dd05a9c29b528128bb1ccb70bf199bb2b3d5b876f84f886be703fd34aa7bd853fe5dc45febc7f945fbfc82f0ebdf30dd6f7144c9368a8b" },
                { "lij", "65564a9a9db3002c2338b70f28d136d4534be7f287e495e0728b7b7e99749c5e33a9c8ba6da2f60b9f2e77595f302a525ed4c54522af8ee05c5d49282ef7fceb" },
                { "lt", "09a99d2be1581c693933a7ab1c0b30e37a6e1cf931ceda4d8b3632ada7db8bad1ddc3691578deb80cb22e030df3b130c9b963ff3b200fe5bc3eb1e3572d9d1e4" },
                { "lv", "cdd00a560c068bc799f1e4df114d380084c509eeef843d101781f3f07b6bc6ef185a78cd2c38e6924abf6e3bdabf7578b144e255a649006b0920690d57f66345" },
                { "mk", "886e6042901aea60d619ddddb332111c7c67a553a1d8ae1496f19946b8a38fbd92eb8d7306a289d800aedb8c1355916bbb2adcc4cfe6d5b7c6992058ba6bff58" },
                { "mr", "715431357a8184c0a3a3f3e7f5cf79537eaaff5ce8cf47f2ed7919e9bac61c6480ff7927352554b4c0cffd541cae67a170aa19570ea34ee1af613bc758fbaa98" },
                { "ms", "bc654511549bed4fe715ad5f9bf9b8d23fb4bcb4b46096bd8ea1fd27287579cedd77c4139fe888387e718029a3c0d2b0a232c605e7db4192fe94bdd5333cc551" },
                { "my", "7eae04ca2dc39850dd986ee6290e7badfa969a2041c012740ac0ac84a3710ba11cb3d06f5506849e14d71da71cde0cd5ae1e38a3ca5e176cc03efa04ff52e78e" },
                { "nb-NO", "b2e5f41862906c79c9339976aad90e45557ba508d0516a3cd61fd13c2d799f8a4a6bcc3470ffc7c063bb599b4db4093ddae9fe120009e5a15a48cf235a2a601c" },
                { "ne-NP", "14669ff4f4e46ec54a7b5cc40a504983cd453ce376e9f62a34e96e14964906cde9c92cd8f7830d22d73559ee8113685c1fef7c2f30c4499a985faa59014185af" },
                { "nl", "535cfb50680cab15e4e1eacecc8a497d084fc770203caaad1e370b0e53ddbe7d782b17bf7aea708845ad28616e50bb39c299299235f8c7e96ee31c3d56ac6c49" },
                { "nn-NO", "5939d83a18442c889ac9fec82ec80c84a3f86b72ac4ea5a33f9032d62655a30217aa37809e8d7ce48fe00e77a6905aa3ab3f66b36f559aed6cbdfe45e7f62c75" },
                { "oc", "b3fa36206f840a2181213ecfd2be85733094d41f4c6d3825afb5315287d2a5f636e803b0d45ab3dcbd4929dcc660afe8d982bcfe979e05fc98f1926c3c0de329" },
                { "pa-IN", "fd6cc2bca88fc0f6e9356ce84f6b4ec52cde57386879f06199b61485e853d914a1549329ba1751511c62aed1ed9624f211c92d6b18b93c5319edcba821799a83" },
                { "pl", "f1d3b4c21ea7ba1f530bbe90282a84a0a3c428c375ff3a4dc8cf965ce9d4ad74c70e90baf952e353a3eac8d15637a68af0ca35f863de0a818b4d97c104cce047" },
                { "pt-BR", "7a534197c34da21929281c1c30fbc73018d969ca719e63f29587e6e70f27fb0f56ccaa77cde1bf0a5cbfdcd95a414af3987ae071079b30d5753bf6e677f8edf1" },
                { "pt-PT", "914cb935807c651d523ff0f90e9ff7f9a141382c83479bcb35b0e1065dd7260e8b6fde24dde6a34e91366c5aaf89a9b086d4a2482baafc7f94b27f81be619a3e" },
                { "rm", "3397421e11765b9701907f6a8ef79a63e3221958cab94379f390c3681d503a831062adca17480bfea03910fdbe80502c80534dd11c263b6cb51ee307337bb72c" },
                { "ro", "9533419e581961dae0ec1bc07883b3806b929061c6c4cc84a6a2f347f06896c8948ad4c1be2c48f9f42cbe30454e68922078721c740125ca80d0f6ca5fbd1ebf" },
                { "ru", "e852711dbfecd8e77541ee6e9238c15c5d19351fd21ce02a49011014eb9c518cc70d22a23d45cc1f7ad3e70294d4bcc70c9fac6525b1b83c7feb98c186fe09e4" },
                { "sc", "70a392a39d5d91a8f8a1c4701ae701598bc2dc26a5361ddc4adfce3c51358ee96a6e5c0d88c269f36064f09238149d014a6408dbbdd6551adbeab9d74bfbf5cf" },
                { "sco", "594986d915578bfa3eeec80654a3884c4a22f030bca34c1ef4bd2c11c4894e43d732635c3669a95ee207d59ffb348ff75866f2925c6376839d0139c427a3cd40" },
                { "si", "43dae2a9712ccf90452816c3a5e2eb8854eb555a2a7dac19ce7212ba3888202ceaa743dac3f9604b6fe1542936c97b74efd357c3d596da99945435990a2bffdf" },
                { "sk", "f31625163246e431782dde30d900993cd0d466dd39d2a74b74058b9b78a786260a7554bf171b84d1edab5c812676244e47864950740c6f9b426fafc7cdd377e0" },
                { "sl", "c3d6250e129be7e5d56d0b121dd552589d63718c237dd30309d24518a096e80a8ce4c2e99181aacbb358651a4679d900a23859de3aee2c506a6aadbed81dad24" },
                { "son", "9476bc58e7148aa0dee71f60c2c7811636fe74f687b88483c575563951b321d6f79ee5a1ca319f8d3f6092b477afb2fb6c24391115c64b465876dbc6e5e192b7" },
                { "sq", "982d5be8298d6e61e777861a17ad0a9e5d33907eb0577aea903020a664bb5cf24e98c5f8a12a6e33af8bf52cc64c4bd057647000e64cc48aacf3cd7cf3a7f614" },
                { "sr", "4881d79c1483095906473fa6f49abf1be0271df7c9331ca7440c708f5346cef6c12b9a5e8268485e4057c1180c522abfb65eb72fad1ff25ad06f9e40b2efc228" },
                { "sv-SE", "94682cb3246c198b07ce6a4dc3d35a536518eb129aab4d6be2a19861d7e1dfe0c97faed7c8b3d3f6481c02bba3291ab69e941ce780a1ef971bc2496ccf577806" },
                { "szl", "9061891af4e2cce2c0ad8db121b580da9b0f6810aa417ba8964adac3bec63b7ff3a2da5afec4a5731153b43a26073b6e60291a8f0a6b577c65e8f2644718b0ae" },
                { "ta", "97011030b404d70e77f57db79b94de9cc0e745eddd9b63fb1808a96b691766c65f14001647a7290ec435bf61b4fc87966b8a6a210f9eb4af8116537f3ce892ee" },
                { "te", "e6b71fa86dcd7389c43749d978435043dd5dec9f2462ce9d276408751671acd3eb7bac92e9d106893c2553974d03c5280162747394327d582c0b734d6228f2ee" },
                { "tg", "e081d3d23a036641b477e299fba4df774ec15a9a96af876491ffba3afbe2497fe207827df29707af64a2512fede69ddd8daea1c4d92845a21862c18fa2dc6194" },
                { "th", "3d8f5a813fe8951db5ad57178c526fe7fcac24776231c217b075bf7bc7eff2736ddf920dbaf56dd9831a51b0bbfeaeb43ad6eeeb8c99d86e00781a7658b2158a" },
                { "tl", "72912e56ae1aaade288f96376a9e569c74dab32c0b35e347a3dce17cc8e923d931356ad6ab231ef341ecbacf75a277b39b1826e26a5629c9b9a4e5d46cec0355" },
                { "tr", "bb0ee3eb88523afa8625d1d30bca7ac853428311a83c79573b41d30bad1aba81e0f954a9005d8486a17075c86dd489011bef05b297b6d59e74eb4ecae335aab6" },
                { "trs", "daaaedf98cefbf7cbb1f45e5f0e662e271c74bf3633053d9a3920f8146f2db73c9bc4ef4679f46583138c68a0ac18f59c190e8029a43406a6c754089b5cc0fd0" },
                { "uk", "b99f66dac9cb14662fde91152b36500c8ad2d3e29f7ac6c9b4fecc3e2ea8e65c80ad948ebd797f2f12d3f3f1a284c46dd8e610ddd20f1995c8c7de6696bcf1db" },
                { "ur", "96f0e031ef268a24dd88f0e1f6a5bcac382073316eaf317dfbeafb71a6a53b90a5232ae248c2ef3e064a1b98697a5e3f29b3381ab864a7589cfd7618a14f8e64" },
                { "uz", "ffa1bdeddd9e6c1195f91a1fc55f213dbad030b2fdd9b8edd96d4c0776c415d30cbe9898c232cbab4c52b3e3a219e5dfc4b3117795526863a4aec758f5e39e5a" },
                { "vi", "265f8ac9e335873e441323aa9d28d7628aa9932e0300622ee85951132ad8cf1fc5b10f02bdffa2074790719407182592222be441fe7a23203286ce6e2fcda684" },
                { "xh", "087dd83bbc7f39af13ace1a587c9db5583f6578bfca1c297007ef52f56b29d1c0f83b97e4aeecbcc2e4281db0ac8a21b831e4da08d65a634cf7fabf6eec4aabf" },
                { "zh-CN", "68d09f3dc538d4b81ab9956109d05ae096599a810823dbb7a564189e51830a84f32aca60a2e8712fa98f43b3c8150b8860dbc7888f8428ee69cd1f682644b9e4" },
                { "zh-TW", "c595e4026b5635c6a35c5efc2d1dc668eedf7ad1a446cb69785d397ce3765f260352bd2e2e7bde419598a3996d54339ff71d0c433f485a935dc0955446717518" }
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
            const string knownVersion = "117.0";
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
