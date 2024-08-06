/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);

        
        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.14.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "a3d73ac7ff535964ec613a8973726d2899f2dda83e6e8998a288fee1f052524e16e716d28c52d37e7fc9ec8d604c1b8c4f1dfc90dcc2830d4cd571356ce41c5b" },
                { "ar", "a7f8ec6c71f5ea92fabfb8867dc318dbf7b8fc39ad0221724d3d04e3957d6c89139f9d82f468d8f39b05a7a0227b2f4dd4a008f27acae0607c742f7868fa559d" },
                { "ast", "b0fd9d80499624e6d9551e4a5ab9eef024daa0643b2438be86311532a2b167f1f4edfe91496f5e06c623a149852da0d69bf412711fef54d75cf6d387a5672e93" },
                { "be", "1f28a9e27ae1e1691ec72194f7df985f898b6fc9e85b32bda9b332bb1200d36b364dc9f744f5524b842562584b3854cbe6f6ac90c4f73708af76b7c049a66e17" },
                { "bg", "c6fbdd8116e0d41750029c2e22beba29643c2314bb8419162683bc15de89f080d0e61cdb0b63a0b7a5a42364814e7c5b7dfa02209dfa7665dad3c2ad8f494941" },
                { "br", "ff82d21b463b86152f40a2a1ebf745687df054a5444e12993f70cf1b9cef97a498e0459f45d746e9c2ee5b73893faba9866798518d57911e2e69cea08798aa6d" },
                { "ca", "719786e0d786faef92675ec86bb627ffc983e8ec1f29d554b44f29bfd2e287d61647bd34e9061395d9ea882eb360fb9749158c89ccf92d2cf1f3fe79d76fcf18" },
                { "cak", "6b8bbb9675cf304e3a889c654c909f3300d47d1ac3d6b18f748f333cc32d78cabf2ba52edd9e67978b61407131aab27d1a83438a2054dbe2a8a4f388f1fced87" },
                { "cs", "7afa01e83eb6832be3d53e9ea0997d528d41d89ba75a5dcb40fbaedfc852b2e558b54fc26df5dadfe0c44bfab9b2e94da0fcc26e71979390c980fa29528a31a0" },
                { "cy", "39b833fdae2340b7cf15d502b79348ddb2b4be5d7d47b0e358b950107afbb62f44f0516627a5d4c002d4341de21ab4d0f411022606e3cd4a65270876a651b845" },
                { "da", "1ebacd5af5243db87a10add04d3d36b903b86ee6eb6e7fac650c15ba0577d880f39524c7becd91f32889cf62bc8ce942ea4218055281fd2feb4245602f364792" },
                { "de", "d41fb3a101944510b3ff684520d5cd3b900639d0df46864a5bd2cc890c853f0d0981c4771f9e05cc864f7a1363d23b77790bc465dff251213e07dd8f33fcb0d1" },
                { "dsb", "dbb4bfbb0bc77356a0e771760fcae8bc293a6ec3e71a4ae65220b5836917d54da9edbe6ccaa7a696be5d77702e2d2b665415c73aae61db9de42bf36d6559b385" },
                { "el", "3e69a04ce76e2267db6d88126e5adda77c37785f96b02008f0046b317c3c777ce298c118b54a5c6657daf61f3cf66e909725b2566aec69a9149a2dd2fd5774cc" },
                { "en-CA", "d4d916f3669965a727efc8512a466ef2ecce498829256c4fb253982a1cc570e8e2c3939d90968a72de4c4ac015fefc32c7a29b0c1dead595c1805d0253852f6d" },
                { "en-GB", "92e8fca08f9cfb58d5a71461d5609a3c482b75ad851763ac250d8d36cefea5c04f2fd64962f1af84e51f50b4edcc92008026a6fc275046dd8b3b058a665b8561" },
                { "en-US", "2c0f094021a4a27b6829dfefb8701100ba02b4f03d9159ceee4b6c4a39e0aff2f140e1d86a2b2657446907aa943142ebf012390b523e36d442de59e3305c2e35" },
                { "es-AR", "52e65c71fd2cd8d751a2daecbd715f57cabd8569a95829411f49c4052c8d4bf8776339841251f22f4fe8d05b7fb6198a9bd7d64b2593690b4be6b9b2aa80b5ce" },
                { "es-ES", "dd6bfd912e25c57bc952d1fa76ad09cdc7ba86d76da826bbabb49b8e6f226a92cc242ee6b36e191b6d632000c0f9df38233b2ae27747a747431f48337bfe1f27" },
                { "es-MX", "fc87637c91a4ed73d400b043fd27bba94b25a617e1ef0b5f9ea9bb7f06f22144c231d08932e1b6f1d3d0258172aeab0c75a247989008f80fff97acb31d383415" },
                { "et", "d3ffd770e32d8f7e2db0677eb0744aa41f65a9b2d8c484ecf75016503e9d372dfccd6bfa8842f3479df11eda1c4049c83981c36fbbfe02b75327d42f4f13e2d9" },
                { "eu", "dff2c7eb896416842f79ea7d5c93da7030fdf1654651d090d764be1b71d1d0ba1d81e2297cfb00b78805a828d55bf049c68752e185215b2bb89388c3578d9e64" },
                { "fi", "0ebfa1fc5d93cada57263ce8118b9ac98531e60b89fcce276082afea24368b4f5f11a47e26a3e4330e11810b5a61254942172563418ca2e8bde4b6f8cea29020" },
                { "fr", "e3ba15080766cc5a14495ca647ee6d62443aec8402783daf75d7344fd71234e772ce650bcb9509af15fbd5ddba227f7e317f5d361b5e7aaabeff6845f493abad" },
                { "fy-NL", "4a426bf1a97abf575916f2ae45bfc2d41ee65cebdc08a0f1d38233140c78369835706fc1b78892c6a95276c59c87dbcd119ea42f88fd735082ce496057afb5f4" },
                { "ga-IE", "7329070a047584ce49f02ffdcb561819e180a91603055bc96ad4ff67d0d645a6881484bb750ce274172999eeaa416222a20b803814e6e25ceab4a6cc02fcb050" },
                { "gd", "7a3322e8fdf18e715fd4f2427c1d19e4195f9231cf96c076ecab449a3461c27c1d58fb716410e0e68c2b12da73b4ceec1aa4a0165eaf287217edcd37233ce15b" },
                { "gl", "43064f895021cd48ee4a5ccdf98f5562429332d53c025edb9df88564cb93a6518f3db51227ba2d9d1f4dad9d8d07ce2c10fcf6324fafe2394b459fabb9c53e67" },
                { "he", "2fc1903d9603385e2bb97b84e8c7e822d509ea4f8ac29669d13dc5959364963937a1a54ec53c0fe96284cf9463d1a37f5fd2ec15e13416c349191872fa350d98" },
                { "hr", "9739d40caa0d94babeb76089799fe81a87d2389164193041d55729fb1766576db8d93f646762e855e0281d84c37983776d167379d515812287107e9815c43b92" },
                { "hsb", "2b2872a555fcbae934c2fc299d7f1382160ff852d498b05bc856bbce71786129ff2a7874655575d91762292348cc77323c6c0f1e868edf964d50c51905935865" },
                { "hu", "0dc3142ec366c15f55d96a7b00bf830bc49ec1e9aea85c811caa9ff69862b6b68aeb9d15d5e87eebabb026d744d82b35a32fb0e6eabccc22d45cc890f150232f" },
                { "hy-AM", "f1527552cb76208344713781c4e06ac98f8bccda0536fa2bac75a6a42af461e02d1a2d521ab413849324e5ae6e592f5caaa806290328da46158a248ff4552c70" },
                { "id", "bef0dacd8f4db504aadce22825e584288f84eb6e5e8ef25ac26d15b83af96add10556685b569e91a263c6ae3941b67a3f19cf648d0edb02f097998291fb41e49" },
                { "is", "4e6e6b4fa3257ff1708d2d7052f5afa2c9b28cd87c8b6e505f333f1327f444f4596ad10d8965dcdec829aa0c133fe77c6a8d3815f0d1a5dfe123f1b15dceb1ea" },
                { "it", "38cccb13ba6e9f88b0843da96bba9d1e893d6d50508928280bda8488759faf9578c6ff2163d085a0705dde7b983ac2d212f88d7885b38487d0635f6d67bbdebf" },
                { "ja", "ce6a7f19b16de2f8537025e1fa4d576538c322def536bfdeaf83bacb2d90d7b26917a8c28e67b70acd480c10103e47a88ef778d7006107a23170657ff7fc8784" },
                { "ka", "af4f821da3b241ca9f4108a3f2ef3d8d0c36a88fbdaa63514afa247383790bc6b2e9b9023aed1794f49872663675efa609b11cb425dd466f5a94a184fcd64b4e" },
                { "kab", "5d65bd49f3430741bfc933b983cb682975635938a239cff7d5a2a13aff395d66d20dfe65f17496761fb205c6736e814e4443b80bbbfef75e279797a4acc99a3d" },
                { "kk", "c5ee2f527e3d435b95c753bc38410cf54b79f12007914945770c5b6e81006a871c41e6fa614d7c27a27d0af09150d94211052431b950a029a0df5d957b9b21e8" },
                { "ko", "6307356ae5b873d1d4081581875a3e958b622e839a440b2a73877fd17830a62e5560ae816a21c00dcfe6b6921b419568f570dbc7905204351ea67a910e52f6fa" },
                { "lt", "503ca27b243ce0ae7ea3060dc27200a09e33e88adb3d0110471214c70322bbcbcdc053ccc661ce27c64d78722a2e2848e8e496ad7e07f53c82c8b7e336b8b440" },
                { "lv", "fa8419b4f615a6bfc1d3628497ea62f5305f6b652d0d04eb1c96dccdaf918d697baac29cd68b4bf0252eaa097b28691730969acf1b1f8d56cee2a16c3602dd75" },
                { "ms", "de0cd4f3b87ff701c32638bef5f7f969739deb877d35fda573dbaf5b966c398a2f98f6768a024f2290e36c278ef0ed7924ce27b18c5486af8dd775e88868e53e" },
                { "nb-NO", "aa284965751a757f88ee91ec1875b2873790d3293d82fd369b1af6f55a5d73c417724953738a43ddf2cf405593917ec32d71fd86885a932affc97ab671a1b932" },
                { "nl", "2f9c57861440e0cf8c8e0cdb51b6f1f825beeaeff15007218661cd1441fadaf11b97d8f8a14e4190c7d59512647ed0a56f0ffadb9deb686e57d9e59619329218" },
                { "nn-NO", "1a51faa61416d8c2f90a60208bd55e124127eba377d24d86a3e73dd3da9be034e4853085bce8d5518dd2bc19f04d849a2611c4a8c4b89a93c6e4e1e8033f8b42" },
                { "pa-IN", "b5c713b91fceea27b3653388c26430db8bb49e3fa43633c89194862da9bc79e195238c3a39845fb0d4caaaae6d652de24bc5656f7f706ae073f0bb6e7714eeb7" },
                { "pl", "41adce22e8c86405ff1925b2d84a0c2c0b0d00c8b20b116acd37eddc67c76dc1537c77c3505bb71b4ff178d1eda2a64847adbc46e6dafa1846bac3e572b7fff1" },
                { "pt-BR", "94985c8d5523baeadbb3890282b43e1b593d3a470b2c4bf56c62143747c0270442918248503ebd3506be51dfac1b58b7d0c98bb72131e88a424ce933601bf649" },
                { "pt-PT", "afb37b592a3bfa4b3c96036674278f8578e71c11e3bce8a6f8cd4656dbe28d4b85b32c93acd514aa353d73fa28d9ec1723b3371f8a40db34d60d594a47f389ee" },
                { "rm", "bfc19c13102a62881d56df39e1fb8f55c860d14465e35914a44db24523b63e0e47faa49335d4cc65854a7d8083d18506e55e19b16b7bc17008a8a4985171618f" },
                { "ro", "33863cf4b20aaeb8672d7a0f77f59baae323fe13b6aab4dba1fdb5cf80610a07b6f6af39be27fba5d4248376569ecd69d4716f78b4b4912ff43718465dff0db5" },
                { "ru", "189520b20972e92c6d46f04299ecbe7fb36f0c406abce92a269c57b602acaa7632b39e008c0a0d7d1fc6280470557730a2b4176275e0d1c97f4b0d1a85cdea22" },
                { "sk", "a8be3048a3678f25841c447d97c8d6606313d5021dcf5c4e63eeaa5dfecdbd70395eb25059030fa86ee9b100ee71a07b860eef0964e888e2f21c2de6ffae2adf" },
                { "sl", "6c5124dce85f82b35b4f14966fd813434aa2f82dce9d7aad276aec7fb066529399eb430d844e9f2f6a4f2dbbaf39823a2cbafd693708de59d65ecf636c2927ca" },
                { "sq", "169d029508574f516268ba75588bd9c55984c51b58d5b58e9c802f193d2ecd0685f5c689c6638ff65d0d955905f95f1420798e671c11944dfda29990229f9325" },
                { "sr", "7d358866971d0380e6e5522079504fbce4f999f253d7e5af0901317b6733a6fb5f9ab05bd0e632c127475ad30f846352a5c46c82564af8a46d40e902804dd560" },
                { "sv-SE", "0174a6cc67a23029a05a3a068d0e4fb43a800abb81eab532996d2baae5a74d5f37ef927778070576f1f3d6adddc3f3525ebb39215443d46b0eb09f6bf90a7e8f" },
                { "th", "cc8f3d5aa4cb361f360d5d573d081d47c6606576f23ff67f0dd3695bdad33255029f8b4a6e7b6c8debeb58ca6a93758430bdfa87f0a5a9d3858497ef74f9c882" },
                { "tr", "4a30aee03108bbde479092f1ace9412e35aca673e68d584027b1912628202f7cf34c813e526d1c16f838ae8e1b476864d1873dc65d2d5af1cf3811f547a84d76" },
                { "uk", "4901efd38125ce5b4e35d84ef0db8ece7ea4e5a73d3005a2f3e9239b8dc3a20112a03edd295ed2333fbc6a948d21813115d3901dcda1f4f4478e15d63e1f0e00" },
                { "uz", "563f905cbb6a838dc742ec66390fb1643bc7746cb4f0b5cd00760cd8990a424f471d7309868faa066dab7749ce02dc2d2d18c9a662e53250435064b74a2b7787" },
                { "vi", "ca9144a2becac989d7ca5528a67c9c0956c914c0475f63be664554def2826d42bb647ebb43ce009b640eba2091c767216b30540b9bce31d662d831b7c9ca3bcb" },
                { "zh-CN", "ffbab410e34269d02954876c26bd22910809335a9cc5e1757d63f09b1c4e6ef6577e0cca2789e04b99f0a18ea568bdc6ebc59daba1732eae4ae3a3e8334743b9" },
                { "zh-TW", "282139dbb75a7de006641879098d248f31e2379f401a2bcf9e4efd600825e1f971e61470a02c8e20f01fcd5ebff1988bf399e3e083dd91f9372169481db97f52" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.14.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "252d961a8339109a7e277df68819ac0b725f37f16e58546b9e5b6c01afae4269005a45ccb50d9942920c70d254a177a22c6c718f62b10f2fa1815ec500b5733e" },
                { "ar", "406cdac61f25ced0be640c92a3f75d86f9416a0e8bc36d60bbceb3d4b76ba111c1592b8167988dd34ac4f58129b2df6fd52768baf9ae30abbb0e896a0d1c9f36" },
                { "ast", "4d7ef1aedef0c5e7dad7d11671232b0e7c6120cef08c716b2195f2bb6a2c8419ae97c54835615ae3432f8226dc27477182d40b8cf6072e817b968e90fe72b977" },
                { "be", "34fb95824ea3719a21f451bf6790c8960acc30f67e015e5f67b016348c83af456cfc04d879fea651e9f50e32608f6ec19eaca70f9e7b503d0cebe969b0ce8fe7" },
                { "bg", "0687eaf1336eb20105441eee4978baa915ef4f4c636a219a3c63aa6302472ff7b831a9198d9df2d807a6aaa5c127e50f36d174aaf771b0f4a624d2f74d3318eb" },
                { "br", "fab2aba6518821fe3a81d4c759c1afaad06cdb75976b5ddb70009da5c039ceca40fae821e47f81be456f205faceb5ab01dfa731d7c9cfdb4b773d0adbf61d1eb" },
                { "ca", "25a341c5297c29d61f15a14895557db561e4c71e9a9fcc5f21ccd5f78c90e14ffb14f666a1b059444e62b04744f0c31f9aad94a64b68b1c0a269aed8efbd933e" },
                { "cak", "bf8901be331d345379de08b873e611a66ae9465555de139a8a7d5cce6211290219385b5289cbdd58d3e94fe27563bdb164427707e324ca7955e132ac931541c8" },
                { "cs", "790ea10c06a0d6764f64fae0aa58bd3676f645c874df6c3f33ed31310ff710458c8e3dd7d82fa4fa070c63a10cc1778947df142487bff5803d48460292101cce" },
                { "cy", "9a4bad180a3cc4ed7214919bdb7e147623dce965302f02ff4c84c23ba3d09cda836eeb34fffdac03312b1eaf81dedd7fdcc2b7df0ad1eb51e5c8b13f679f7059" },
                { "da", "c4eb7ab0882e1dc39b299afe800bdd02c4bc5af1d22551355672e0c6031c42ce33369913d846e3e9ea8a0fa7f13f961432bdb58700b6b4103c08cc3cbfc0ab91" },
                { "de", "49e78c31e7234508a4a04ec1b0fdac2346aa0f1f3f24d531efdd9fe1c0a85b9be10aa0ab2c52810a325fbe57e16b8ff6d564688699b1ec19d3d17da882db460e" },
                { "dsb", "ffb4a9030a7b7ad81a3e461c14dd8d93772c749f7cac345327f06ce3f0828245925a96aec1f57c71be7237a1783fdc08cbc3da4a7071d50a45e4afe324bf3277" },
                { "el", "037c8a776e45d6026c45bafb2b11d4010bf24a67ddc4957974d4ed6f7361a9e3eef099fa035298bd75434cca80df6709e35ff4a9cbb3c937d0a2841a3930b358" },
                { "en-CA", "d2c11f4d37f064ca3b93ea6fdc15bfcf89b5761ee6f9c2b724d68e7fecbf74736ac72e16bb9d2282574fce840223a6e7d64f519d97efb9f5a44f00dc5dd3f53b" },
                { "en-GB", "cddfaedd741aa6e248626a131da32ea5bf9b8455de6c576bd76f0182e77a8f070bb4921313e5221d958bb248817883ccc79adc2a43f5ddbb572478f837fdb1b5" },
                { "en-US", "4e84f6d51f64ef530a515cf0210bddf0f7aab5cc8a97e7f8a70f8fbaf56e209618d9832f9583352c2ecead97a5354e346b26520c17de934c9cffc28c46f5edca" },
                { "es-AR", "2312ae110b008a0582e62288f1dd14dd2644ad48d220311276fbfedcb6a68ab23a2b9afd928c2126726da5bc7b48a04e7ae0bbff7e9f6a26a1f29627a01f3253" },
                { "es-ES", "c7e3e0303ca1322066dbc9b4f1791bb8bcb2744681ea2f872457057d091d9136bfb17e3d405f665d6bde4b1a6325124e0d2362cf0aee830439617a6a7e781146" },
                { "es-MX", "fe020691301e04010432a8747754af4ae1857b691a765152ddf7012284389487a456cc3a8bbff1c33ae3649ffdec616fd831cda76ca9e3459f35e2ed3dbcaa9f" },
                { "et", "f81e6337dc7bc39a0e368fe32328a313c1e86954389dc7e2c185241a799bd1b2bfeb6fce848b510714728d5bfd950effb092b429d11cad4fcaa9d18fb2639034" },
                { "eu", "a3818707e82aeba6215973d34187af082cb272f93838456a9659f9f98454df7078d8dd3cb053f00dfd3d9b2753a32930d7798eb38422d8edc5cea707114444d6" },
                { "fi", "7945be6ababa949b8931c66e0febb0c05afeb55806e0047b7eff858fbb4c0f515c8be495ee233156b94ae6dd96db12f3041dd471e03dcbe6131ecec9aada08d6" },
                { "fr", "00c753bd6f39a0ec8058a9c729557a62a53d7854098673570de26eb9521d781750d05a96c6ef31a090addb8a942b2ea51608e77f0e319b8778724fb609bc5d4e" },
                { "fy-NL", "5722a7f22aa020ace303099aafd8ed19f70ade73132cafb6e6c8b1984e581a4979f832646ba9cd05b8d4a987e08a40d22403e3275dd3c629bd97c0579024257f" },
                { "ga-IE", "c6a99585ceb7bf937fd2a7bf58f538f55090d74316c910ee68b6c85707120893792780844ab75697b32a104adc64175ba7fca8330b94613051fcc7c9445a8c14" },
                { "gd", "63423d1bd2f5d3de92b40a97a811756cbd638eb91414404851e2f903229f74d75fd7fe43c2b0bd7aae7f6829bb92e63ff2d82ad5ae4e0568e677d06e19a3a5cd" },
                { "gl", "94c856cbbc1ed4bcb7f442141b4609df55836ced72b096fa16cc7f825c9ca35f0545f3022c2c617624606c4ee99173739f2f13aa0efc37a61133a0b18f43879d" },
                { "he", "1fc5848e6e33d708367dfc740a8c15a6f7631f7e9a04d5408c9e8bd403b7095e50e0f3a9de934bb1638c3f67d81e7b7ccd6917c35b6ff1820eece0efc8f41cd9" },
                { "hr", "0170edb39676f4a2fbb9bf724c3f35d2a1cdc0116f346f043dff01da86c470a8d472f5b1d345c9fbfaf6514374421dcff63ab87e268fda46f3dbf2018e943130" },
                { "hsb", "e5cc6172d7713adce60377bd49c055315542a1d6f45f4ab32d550d786abda3299a6bac2fd620721070e5ee434741a6f1107ab0629410e33466b82b30910ac0a3" },
                { "hu", "d223f954b3b1a4f4c573961eb440907476d28dfa2ffa5f8292bbe7a8e02f6c870d6e538739cccb6bc15819c7facb4771f581ac510f6a472c3f69f12b153b8d2b" },
                { "hy-AM", "4beaaaf48eeb543a213f747fad2c216debe33396dfc4ff0b9a9c504bc44b518da3726639271caf4f05a7e7bb8e64b6b551ecd1d3e380dc69545b2821d0547b70" },
                { "id", "04105f4a265510623ba355489d7dcda59658e4d36c3f7f91f5b1b45a8870a03d750c73e0260e914caf1953640fb959d85ed7b37bedf3098bbd381b85cf5432a6" },
                { "is", "ec66480af3f72f6d60e60e6a60572d88fe3f24a23f4bada936e57adb1647f2aa832dca4aef6b3af00d96392d84d29ac65521c38101d68adba6c11539eda8ff4a" },
                { "it", "9367d12e161db9b5b8d84def6f74e67d6df180f479084d68dfda20168b6ee8f96b899f8b71fe441bd6c32f32104e6ba52d3efd5c82fc3f9df4ae6bdbfa127073" },
                { "ja", "589e910bce3e5797b85650527205a58ae14bf660f9a645d1ae9fc09d1a04dea4f5c478b897e0880d0f354cb408e4c567be7c0cd3cc77173fa8b4c66091188eb1" },
                { "ka", "25eda34d76fafe0e2bc52b24d31bf524670fe8c97c8f09c6909f838e780f03415ba0fa34e23abe51076bcb6ed8b17f0f7b76a5be61234ea805dec49bd13d0062" },
                { "kab", "cfadbc17667dc8743b79c5fdde0e8ff9d87a4e6cea455d519f1545e84005dab84c0f0e9e04178c2bd2dc2a234e489e527f9faf3c511e064e04a612da370faeaa" },
                { "kk", "2c4e3d1cf33648f075a0437e97aec12b60902191bf29dbb32f83e334f3949f2214c4a44123b276a75c2a0b595485bd0532cf7b0947064ddd3f3d8bf1518a4468" },
                { "ko", "e75c05f6ecf5de27f7f2166f726de64955a548e06445fdeb06ff58622398f21220e43042f8acdc86cb2db424bc26d9ad0b895a5835c74a34a0d030704de3f053" },
                { "lt", "63fa8f9693df70fb763634a89892f77a4f534fcfcc5de25d8847f8a561a747e336933f862c7b9a45fc408fe8d3900acbcf19b51b79165ad02bcfdf374f27e243" },
                { "lv", "09f39591d05b10c2349b3047aeffee9a837b3bd50b0b54d268a05f6e4e12e318188e0b03767f91c77d3e2ae67ce91a926d286fe38dfe732c812e1fc1a83c3403" },
                { "ms", "e68fea660eb50eb08a66e8943e4861a52eb48b1d56eb8bbeaa51873b466956c276bb526758b1a7b98c2c26c236baecac2550b3694c158ab4fc25062185a9165b" },
                { "nb-NO", "ac006cf96cee31adc324e696663ed18b713ee26840a5298f40b0cfc9e7a3ab1cf76e58ef799aa5b692c9e72265bf31e734c0a52f8c8cb1951e7bec1b040b7e63" },
                { "nl", "aaa5927a0046dfd60dd4f935db4adc09113e2016429dfdab6b848ff089b0821c743c64b87de585c862cf28bbf1844b5e4e2a653bcf9236bbecc59db906c812fa" },
                { "nn-NO", "bd6178f71cd3e536d578a8a4c8519ef805ac710b4cbf9cc594875c05afd88d9e201e124303f7ab3f985628061b97acf3f74ef616ef9cf8bec07fbb3d4f1fa0b0" },
                { "pa-IN", "ca4f9c10902f3c329b328076b7e69f865901de6351ecb717a5a1b712c325b9ed771085be39462cab739eab997594945b28e1ec8481c09ff705337b59ad6c5dc4" },
                { "pl", "79f3a1296a4ab485c43f823ba93b931998449c6f369b519629e265aacb89bf488370e4dde67136146028eb5bd8c97ee271f91f058a2eed891d09eaa719105059" },
                { "pt-BR", "6bfc69f38eaac286687014fef363847a125d2d78aaf4d835a2e5e4219e598962570f5594222d7ae1d60325473fa00bd000993ccd6c634c1a937c904a80e73fb5" },
                { "pt-PT", "ffc0cbc4f0778a5b58a9deb67667f5863c14e3a71693bdf6b85359052a092652ebc60e02f38ee805d29f1b990d27bf9c01d288cc6dd231c3f40bc1ad0bfb84b8" },
                { "rm", "e63d294618675245867fdb2896000d2bdac870e5c3371c91739a7122490009269d00eb16c56acc54f6360f3a6976238967759d4db9af1105b93aa6a1e4b7f29f" },
                { "ro", "e0a5c85219a4bb843fb69b25ddc807dbe8d4bf40bf4485e86849f79c3bb5cb987ca4658bee060f1651d655979b256d1a1a78200b0adb2d1f572304cb6567cfe0" },
                { "ru", "9588b9861c228d7f6fa1bdcfe0b0127e51f8718eecb8ed8ad07f5b6684a9c786995d4bf4c99d4011535a4364761180ff986fc755d098ec455d861016b1a725f4" },
                { "sk", "8230b50cacffdbbd9a6e7f12019043dab4fba2939fcd8c3f17602b7d3d8b68814cfe76bc2781591e94cd173d6df818f6f3d560445807a3384667b25f2635fbe0" },
                { "sl", "60180b7f479d73969124d76a5300cae2b9ec32941071cf25c3662025114a4611141ef805b72b857e67c494a8b0596e88af32823ab57f5a1f740fed925e6459fc" },
                { "sq", "8c99fe9955fd4d688246df323898643dfc629e3a969482449afd6e3b54742b07e05f7e438acd5c9c9ff395c1b07ec55870be1d39b2ba7181e1fd7d234ab4eb76" },
                { "sr", "ebb69acae232d1f34fa133f81dfe4fa5e1b4497dbe2462fa866ce57dc6017be3181a3ec62df6b36e972594c3808da19cee584d79550580f33703bc198fe1e9e2" },
                { "sv-SE", "751e99ccff9f4abb0590edd830454069fd5a6824d8e130d63b6351ff7d13e9fbece7b057a591d04e5fc6b628e85853161bb406a63bd33108d8174f2b71619237" },
                { "th", "5929b432d8cb408c3dd17b8afa46e444644685059017986ac87fd47204eebd8deda6dcd1c8e60427bf8e543f5fceb36ae61cff9b2f9b44eff5435e26eacb8824" },
                { "tr", "58f76c6599752ea6e1a7dd1091ec6e80217b761e777a24a04efa545b1ea750f37603c840ebb03168e355849e097e95aab00c529e48faae45094a530a74622d80" },
                { "uk", "c7c50b19953fa101993b23b75c9d0e38d8c3da2fc9aa9ab63df1e426ff0ab787eed8cf22d26a5c3b6bdc2ff8efb8f266f3e139ed111d2897b6862f7086c6da89" },
                { "uz", "a1cbdc7e9ff146c47e1ce6beb2030dd7c6d11ec01fef8517d4986dbb5c721e542b59ff1a858812a4ddea90e2443bf443933b8f417868349db592367a15694516" },
                { "vi", "ed4503b4ecfe5a0530bdecaf6d63c03bf865536040c2fdfb0280118df0e9f43e65eaa5e9f3248eba03043e9e56e612b4f22f3d87cb7f97cfe4f459ac935711f3" },
                { "zh-CN", "e35558554d17c86be5b338292c237e66df5d2640b0a05ff341b1b4c0149482473b5d9346548cb892b0c9ef5967c34eb72688dbf622292ade788f401e084d7304" },
                { "zh-TW", "440f73265cc05f47ef95c31fdd22f7bfce34f59281ec05b5b537e72dbc5abe3566583636c932d150c34a2598b1dfbc1b998e05a37b637756004052596f161799" }
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
            const string version = "115.14.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
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
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32-bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
        }


        /// <summary>
        /// Indicates whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
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
            return new List<string>(1)
            {
                "thunderbird"
            };
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
