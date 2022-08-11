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
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/91.12.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "9fb0aa1bc8038412af8520d4a9e48e8b81993ec02137a8a22257bcb7e9515d6ee93da5d5c65699d64e05c0898dfc79815b336a0bb105d9189efb02e53bd2a7e0" },
                { "af", "c72e6798e73188d46b4b5a618846319bfff76b1029a1f6c5b8bf86643e3f814942df8acc319f0b82527b73a6324845eaad0b674044e18e3acd9dbf2aae46fcb2" },
                { "an", "e6a027e42fef27009531ffff7b383def24cd901c57e87867170008e7863ad5436ee8ef4c124e073d8a47a370c4cad7d03d24dda4abe70e0fbd48836d1d03adab" },
                { "ar", "2393f51d9fedc76874b6d7648dcf2202258e6edc98100681177f9b1c0c10db1ee0d5de30eabd0f8608e6d7cf1180abaf05655bb6ebc35828f08c526d1ce6a1e1" },
                { "ast", "01b63a2e445b2236459680945f4217209ac024fb56e4f2c2938b59858a217b2f4a162a639dc09e5280c2809dcda092c975bec2b55fee2eb9f9d9a87e5addbc90" },
                { "az", "f1ae8863c6d7424963a42900b1f96cd53609561370f368ef86e7e66baa8d6ddb3d471fc2c67049ffe910a7e1a1101d3a6675c4d46bbbe63af7ba308679a092b6" },
                { "be", "d9ae1b03af0b6f94bec9dcb9a3c063b3cbd2510f09fcee3cdd95986373c6609141b3b6f4344c54d9ea70b695fe1a6dd92a53365858114e11717f8303cfeba271" },
                { "bg", "dcb62bc24148ba81d28ed06b78cbacb69067c6b7226642678f5ef1ca5d92e1ffcfcb24ca314cddbe958de4f7121021e5fb95e3ef116a641e44b0efab11a4a37a" },
                { "bn", "118e7eb3b55f68982c4d1d269417c306b70fb032697969951cb09d9a762de88a3a0375b67aff9541bd3947e7cea03e3d242ac3e03229da0417f06bc72c3c506f" },
                { "br", "40a3377c1ad87eddd0adffe2e43c4c540f58c45c6b02a2998a17144e509f4035d1745a33fd145dfc3bb7ccc28acba0d62ee9a6666ca821c92baf66ef0cda3858" },
                { "bs", "644296c1668e182c04a942c1f2e528ffbcf1bd83f22a9e37e504fe9a343b1a53fe7b059b0601c467099661733aaaa1607927c1b97422909e763fb2b8f1e12f16" },
                { "ca", "da7b771f86a1ae186a54cf17296085969439f4d45921a084d81b180ed36d3ed7fad56cbddc286f9abff4cc8b07cf94b3435b8d943ee21b9641720c39c80f1b86" },
                { "cak", "364629ff462aa36917d64a27aa2b44dd1ffa2084f7113fc6175921353818efe05b85cc8c2db79771cfde03060c7873b93b4fd495334746cd95af56a20b4453a8" },
                { "cs", "b5e8fb869241576802db8fe5d167d8451be6d90c9de106a9451af61f31f1ddde4ac7cb9cab249596b7399e531df35c728b9f4061bdbb7313bce3a1bb9c8048ed" },
                { "cy", "48489e51c3001f84f5c4afeaa29a3f466d3c8b4f061ab9de398a9b6197e173595141d63b7760bf41119aac18fe57201a6bfb0a1b36fcad0e613f223acabe5e03" },
                { "da", "aa82efe3d63d579840337604db39ca8b3d35f01e3f20f6ae725081b02091e18436600c99ec3bd980424c79e1a821bdca48b0e444a394cadb1a367ba83c0a74df" },
                { "de", "6e02572c7054116786a678b64e52d5bb26e9f818920404f972041af8c7bcedd378fabb858a48b40a7f737b90b71201e97679f8d4daf83d2436818f77b68d3a6d" },
                { "dsb", "3181df0521116b43286665f4a0d7e91fc9c8eb369d9eca0b3f363ad896dd87c23dea1c1001ba62bdf40399d0e8a7299fa4dc620390a0f4df67d3baa71cdb6937" },
                { "el", "ce70762015bb8bd16c71b5608280996aa41cfa980115dfb8f8a2a69df6da74f3f6bcfd1ecc26eea0869210a865cb58ffa1bfae8d5f34a1fec24b737b7d9ed9d1" },
                { "en-CA", "dd30d4935d7c6c9a49ae7617457a082d9c8ecbb924d41c9ae304d0a16614052bd96eb20517ebf51a021a477c184e6eebeca6a8a025354950e18134ce4412be31" },
                { "en-GB", "f1e259b98cb654d3457747693139fadc0b1722862ed770fa73121b54e556bfecbc6be95d86545cd1b0e3cb3b32d3606a3234bb018053f2693c2a818838704e1c" },
                { "en-US", "e68250559ad7e5e166d5e61c957059754506f4d4782211859d44731107a46bd6473e7dd41cffde397bba89616899076628414e7d05f1ac6b9c63608aa446373d" },
                { "eo", "102fc0f5ab657190a424b9e7af1710a7fea2e81861b08b5b6b60db64879ba77948fb0bf4cde34ee6ef9b5381cf0edaf42eb652b8fc55d02ba1c807fefb48bddb" },
                { "es-AR", "165cc209b51588b75e1c8194966e3f69a35afb1c6dda51f1845bcea435f37a9a6dac6c923af0ec5a6d26d33513ec5c8bac8af6a677724159c99aa8834fd27304" },
                { "es-CL", "6975c211fa4b259462ed13160bedc7be8f7418a51f5f28ff696c320de7854932e648a3af8aae9acdb3f9396bbd58376510b3a3624e12ef76a18f2a81dff073ec" },
                { "es-ES", "c0f4fc81f1859c68cee0a6236ca5cce1e5d12abcbd99971e9819d3847e47290c8d5ac33f5b34b7c420f9acb0d6fe36bc3cd5bd26359d81214a92fd6d8d5660b2" },
                { "es-MX", "cf65a55833a1fb61b7fc6d5dc399179e004be58e24d0411e3c836f61ca8b5917413c002e6cc29d8b9d738b445fa62264950c1199bd1d7586c41b7d0eb71aa19c" },
                { "et", "cc470d65b91ed8d9239262806147c9a34ae47186af3ca1a091ecf75b33f4e313fae9f8bc815c6fb511ca91faf8fdbd2940d3683d5fd4623fb2f59a3050875f61" },
                { "eu", "3d788b48a04dadbac779da505d4bf8d94da7f513c3343087f6585d6d9218599b87044b4c5f6debdcd63fc627566bd431ce6c41da22c133603db163f72074bd2f" },
                { "fa", "898d225cff005fcdc15b5abd326638bb394e8e74a969addb2a6edfa87936557ebd4a750cc14365c220e22c48d212918eeec06ba692c9f3a95b29ee536b82e35a" },
                { "ff", "49d4bdcba49cca1a132e3ef4bb511850c33084da7f8a1780879430b9dbdd6cfc8956053a3d7843e92033f6e7e8137035ed614093edfca0fb749d75627d0e2839" },
                { "fi", "39b6ff9b5110da60816e9c79abd86a52e817e230bdc4e63b2d41799fcd482cdd7b5e8c1dcc8bd3cd4731753b11d66c8042c7c2199a1818578714d8f265063029" },
                { "fr", "a69e52a462c79bf9e4b0ff6caeaeae8f10a690aa46fed3521518d2e3942bb61e483ef8e44808a375789c4ee0d839c438ca31a2c18bc88e2e29a4bbceed31bc78" },
                { "fy-NL", "93ccbabb5cff53ba509b62bc643e81fd2b71d1bcc88d3c5cc509706b07bcb3ee46dbc81f0ade28bc0095683c284b3158591a4b964a4db3b6784eb62e011893e8" },
                { "ga-IE", "0db4b37d53a02820fcf898af7de056069bcc229c0de7b19d2d9887717031165649fd2b1d074ff45ae6d911b88fd28f69efd2634f4aaea9e882354d1acb3784df" },
                { "gd", "10747bafdce9e73816d5861d139bd6e8d0aed0753596dc620339462192e006e9d7f051fb80f08d4d205b87fed0c0368d455963ddde345cdf5bbc87b78ec3ce6a" },
                { "gl", "9fea01f8ffc202dce43d471488224e5b3ff43681ddc93b5aa61a1006b6f06ae36e83715f486705efc1864ff1b88a336eeb3d40ad3698f1f338a3b75505c314b1" },
                { "gn", "d03c200cba406e7d1a6ec80a74d1989fdcc9a0ca4c0545ba40b54b216580f3fc3e346f8556a574c45ebe889168130787afdae975f46eafdace9c8cb8168a4840" },
                { "gu-IN", "5f98c8a1366c688377a404d04332588df4fc51d907a859128820d5350243db85fb66ad401d48241714e3ab78c0ad1c7785a88ffbfa79a7da369849e7f4096dde" },
                { "he", "99b91febd44a4481d283c68d4b42c837a2ec96a35a88867eb3863903f1c98d7a82dda6328b922db9c48cd95aa7cb8ebbce9c985d4898793a623399f6b5cdc0b2" },
                { "hi-IN", "245e9637ae041d831565ec74b04f68ccf12afa494ff0a7a7b231f1264285821eb19adbb5fb5235a00ac3357f1fe4a897e83563876758da19aa2d13f722bebfb8" },
                { "hr", "9fa7481a4bf8dae09cb0957f80325545b8ea2e6fda8eeb37ffcd152a492a4c36dc9fef4ad13e59e54e713a1087136d9042c795b952a8f9e0fa726b99e396e6df" },
                { "hsb", "b6dea609264d014b79e3b5d6813c583556ee1d83641a5312a97d910db52d49591358db1e30ee76f9b57b71172bb1e7a365b39d33eb1b6aee8c7422364b6040a8" },
                { "hu", "bfeb2c4e4b4f1f95efd1ac9fbbd0a8be70d5c3f3a2e7c98872b7e8a16c7d198ae2be92665cf05eb822202e211fbe91b717ef694251205eee3415be13925b3456" },
                { "hy-AM", "b064a1ca9a789081e3b4c6a0131b915e1abecca518c7b7f11b0cd4063d1a02da692a5e6126017cab03e8f923551f2dcf32412cd137ba8410773b313e437593f6" },
                { "ia", "6d05b55ae87e60bd91708d1390f1f1682e3a6a604703d935d6716e711f7e68bde3b972e56914f84f96541e635d8fe5a9c804b5ac961f5230f4d3d71937bfa1cc" },
                { "id", "623a66c87fcebc6445fe9b714d9c491a8ae3c6a06df363773cb80d6b8bbdadeaebbb9825237398ccbd06499a65822274907e63a60d7061dcc8207b74ccb9ac4e" },
                { "is", "8b25c5fe61def035413ebb6fa02fed5c7e967eae3502c4afdd4292ce7d239d3df8dfb86f22160c3e290af6b2a7392354a56bda09a2eb7f433761508b8e1e470b" },
                { "it", "b2014e1b3ecba6b567f229a698cd9dd0bff850cde6dc08e1ad99fa81e9a20d581142db634f27ea8e66d1aaa5277948c53672e1196cb5d91c4948242be6900f79" },
                { "ja", "fe64cded3adeea463301c7764290ec1773ab47fd96482a1fa657df998cc41bec37edad99e8ca77a1f369e94f17529ee5fb1a87ac8d13f4118fc7ea115660bced" },
                { "ka", "fb7f243ddde4747d6867b35de258127ee9f70bada755ee3c539f3ab557f891f61ba356cd438811873950581585a72073b581b7e5014de70fd98bc1f400db33d6" },
                { "kab", "aab7da90a1ca3012f6f2fb0f397baf729592c7873c2f33f7e79a84e789130ca8ac634ee17683f70158de6e5edcdd60bccd0e517da68340bb152560c3924ea6b2" },
                { "kk", "c19c9398c6977549bd6a56590a8eee01fd82b74e8a741127714b830a84452be96af09becbf64d925af29f12b5dbeb64eb0b887f4ff62b08851d3e54e6cf9d11a" },
                { "km", "4fdc4cbcb0229fd64835ae8a2f281e18703b94c321397bd92194be1213e2db96e15e7a08b29a6c55d15484e3d8622579150c977e27a3bf4dc2551880e5a27ad9" },
                { "kn", "8a2ca7af9f7f5a6add151cd662194d3b5dc2ccea3bb6672d820c7e27f9ed5a3c6548ac0493f73030f795e9644611b45c04a3241ac3047bad08cfbfbb5cffd0d1" },
                { "ko", "37aa1ce293be0b81db00b7bf53921a59c39ef879e7d01ba980d873ca230d3eb4259018584c994aa6e1e8a1e172431d4fc1d0e813e6eb2ff64f0195949ecd3b02" },
                { "lij", "fb9c1f57421011ef6762fd0c1721394b3ff8cd4f457c2ae15f33d5602462d6e6889d7757d28c631889ba9ee845cb851b0bf5953cc41bc865345279ac29b68e94" },
                { "lt", "33cdb4c05945877c2fbfcec2b69a712e495671085b4fc82efeb69e13891d3d915bffc7b8f8776a4eac935330a2551abbc0cd971f11c573daf3d9a706ae39d266" },
                { "lv", "3d242b17f38cb3e4833fe0d5097ebb79bd1e84137806a1553f80c9c6911db8ceff4dc743bf0e631ec3e01c2d24508df2d1c4ebd80c5e196f539eac5b12dcf9fe" },
                { "mk", "a3263946b011eccd38a5c8848fd37ece069700756af36b223b0b1c386b3250a250c95de364de6c3703d9268050c7a9093e35996194decea8322f3090b6806868" },
                { "mr", "78141588a150c1760ebb6e4abb534da7cf33e04007409841c93dff9460cf20497b8f63810f1e03b7622362c07c5c755aa5b298992c6d489d96e219fc5a00d019" },
                { "ms", "f1c9fbbbfb883bfb961afbc4fbfb2e37556a98f53c900c91f88ab9ba66db6d634158fb63a40bd56c6336fc65e63818ff6a2c0f8ad124a683df510bd878cef0f7" },
                { "my", "be0f1b8acdff86aabe144690edd8eaa88ec639ce9279186aefaafc4f73a62f9858b62de7ea655f7263e056d8725622f7c6fa96cf31a615fd3f13d9cd26284c6d" },
                { "nb-NO", "87c1982d3e8df192f2c08a1c7869dc998591a05bcc5ee47a476dfa6a9d8c404df42171d1f5cce5f2bcec90322d673ad96c45e64854dca740a88a63be780b7cfd" },
                { "ne-NP", "52db5487a48401600af84dd6581453d36cade6e89932d2f9d81bb8129c8ee5cc680c2593d73d0e5661253718cffd17f9afeebf5dbc9858e5b87e06e6547665f5" },
                { "nl", "4df13cb93c904a791225fe802166a479fb8783be2fae236f5f822307e37bf8a76bbcd347f917bd24c04c4e61a7a18c56f713c92a9bf9cbc3f3abccc9dff0f586" },
                { "nn-NO", "a4f914187b1316a3b55174c7d431049e5a1b0be62447b340bc600e4b56319b9e066d24ca5480be347aec2404a4a6f24abc51421890e01d1db9e38dd5d93aad97" },
                { "oc", "48a9b1bed31fe1405781e05718d63ee4412b8fde531c7b24939b81ad0350249c7149912757e31999fca2609529704c59adcb8bc38aa94eec5afaee721ea2cf55" },
                { "pa-IN", "47095f2667f01cec1763094897db051076f757f1021fd57fc9426fd7bbe7ec1ee187755295b7e2f44b055be80308911986a2c5fd10c84cdb5c8d64a31201b7f0" },
                { "pl", "e3543bc4171958339c63e4ff4762c1dfe5d1ea0fbd03622f9378162c590af86f47c69ed49a14b538ffafc8e9d9069da956c311466c8a14d65675ea059f47cb5d" },
                { "pt-BR", "e3059f5a9000e52ac8e9a2493be908001502c51a9a98f5e894f002601db104c481a3874619ecfd13fda40d1cadcbad4273c2b2a5613501318f78d4021cd49ef9" },
                { "pt-PT", "89b5f8f232e22085a0fd546f57c89d625061c59e996c110d9a337a37b2e64887dfb2e210adfd7b6bb6dc24e9fb8890d9883096d082200a57c1fe6b0bde41214a" },
                { "rm", "d6014a155373dde71e6d4dfa08ef63bba678636ae8f4baadf78b507588ec72f244184d34f8c16da2711efdaf4aa37c37e0c40f082d96eb4f80d1d7b62d51b4a6" },
                { "ro", "112b2e3829ae525a7d135db05e6f8efb1b135f527c55a9d351b2894acfd0b12443b0a09de6d3355b1d20522037660b141a06d71812012f185c763672c611772c" },
                { "ru", "b73cdb3459cb00bc130ea30fb9f9b4b8892b602e03a0a74bb6a93fbdf8c2e3c2231deea2161a680483cd4638490f60ddbc52ecb76aec5d0cbe5433b62215439e" },
                { "sco", "d1e14cbb8f3db512bc717436479ea1dbaab9b844c49c9ac3c7fe6505905a7efaa014e7049d79aac9f548d0655e3eaa068a81f1d9cb740772b765b2b42d6261a5" },
                { "si", "14a4e6f0e955c03d2551cbe70f6a9b8ec48190b74a08207e2d5eba9535b48d6469085bdb3c03e70ae4a3d9d98b7365c55213f042f24f0a3d664ffc3c65f4d5fe" },
                { "sk", "3d61d451f34a3e3b40292bb9ec79d127e1f53c4f027e2be310752fcc8f554c92e81f792547a77788ef053e7e698aac0051db3d2d8d26c696f288008ae0294cc5" },
                { "sl", "b13aaeb4b7b917d97fb11f1f3194b34a00683c93c6270aa21f93ccf81475559faff733c973f66bd299f1b627e29e262142a9a55b857c12dafcc1f62e3024208d" },
                { "son", "49326ce5586c0fa4e03aa092c8f40f434e99d7e695924ccb8e0fa4f01191c02275502b9f247cd04befd8d78d6acbd1b55a528c361520502626f6f6fb8af5c8d1" },
                { "sq", "2129486b6a7ca2b23721616f32bedd6295db7a8e47230a8a81702e471118f06d71ff1f6622da2c991c353b8af756dc486001f3d05d5739407b47aa64bc7895b4" },
                { "sr", "7b5f824ce0fb5d6c097a34a8e8bb95699f94a08e1b03633ba42a9e8bd5290e5cdb88a8e1c052434475489788a964e8dfd6c1c5fbee9ddb61cefd4b3fe3051e1d" },
                { "sv-SE", "c2e97f09a91059f8d105d21ec17569cb6eea7484764ebdbda5f72cbba7c3fd53642a3b5a4bb5bff7c24d17fa9beb606d4c1fe00ca00b8f60cec8c286102825e2" },
                { "szl", "ce014fbfd17560708562db2f03d131791892e1eb1360df1f64076048b951baaa59e23231882510c8668d01c650e7c17942a5b70a3e6843ae1e84f7fd060e4a0f" },
                { "ta", "185ecdd8712fd7b07e19c8a83c5ee0816682dd32ea3a84171415271b8aa1db2aea9c4c1ea4d76d893179e4ce83c52b5d7d91b93f5b19e3500c290320a1d25cee" },
                { "te", "b4961f06fb279224b4d4b4965728e9d509a0ccb44a39a373172682c3d0cf97b35c3a813f037215e5098289be136c8c1f2f42e948df66218c081ce870bf820215" },
                { "th", "5798159dc279fc265b95d9f275667d6f5296132155753bcc149ddf6531d67863e7178e3de725a4dd7035224a45651d515aefcb2b45e6816023b748738cffb276" },
                { "tl", "5f733ab81deae638e39fa502e0dd924b5705afad58c00fa291d79eeb22ac87caeff6a77af9335d1cc672d15c19788c67e910564fea665ddfa324e01d9ced57de" },
                { "tr", "f44de71fd73a8c3889da15536ab8a37add1536f30e58b0a1f52a9e16a66c5aeb69d951460885279e6d799dd981d10a4f66ee46cd514e907b7f32cf260d149337" },
                { "trs", "1320cfb0e6ee3bc625f42c97eb0a6215c5c5a77d15f7c8377296a0801ecbaa5c720aec99d14d59926ee90d8dcc407642a9ba8d57365211400530eb31f419ada1" },
                { "uk", "ad4bec23d507b1b3be005bd50ce87298daadc4d6d3c43d0fb95e7ff0aacc682ca1f21b62fd418f8f5b026495c5a171451cec2ed0f6e7e16af79f8a9c850531c7" },
                { "ur", "8354b4e99080b7a7ee3acf294de22752656a5ef41f33d4b057151a5ca9f59b461f9b11ddf5d5a42ccccc2322a4abd31ee4d652801ed70ca13a320d50306dc771" },
                { "uz", "2b836c595b6737fb9659b2159b505524f1a8a283fb10f86c8e4a7b1409f500feaaefb6d3a060926c9086dcdd9343a2feda3dfb96d32dab4d0884f73c5ff77ed3" },
                { "vi", "55704f405490602b33d711ef923ecc5b2bfcdc61530297d9b7557b9c92d5116207f567f951e39fc75a5dffe93570d324949eef40558d1fbb970ab89aba21a7e2" },
                { "xh", "791f0a0cf3f55665b5a359e183607a9a77b62c2b5c77a01f9ab1d2559fc666b0f21b94e654026dff100cf3b0fa8d4f908ab3b953ce54a79c68108f0f99a00565" },
                { "zh-CN", "908b0692c55c38ce9481d59875ad4f91bff4c3847ee58482a68f4cc5b9d22f815d0f49b334205e58bf4d2d3e320cab89ac491ebb16f2c48640a92bc617c30697" },
                { "zh-TW", "0a7f2055d9b54999e972e7e17fbfffd4930505d6177ac48c689c3db935bc9d1684655712a5e8185d298c600ac3990312e4e7c977aab4474c2224bed9706c977d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/91.12.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "d3a70416ac0430922a8e66eae5f1764404b0a966c499ab621e170add26e5c66808eb57bde7860f6af980069fe7738194c29b3fbb3c112e5529cc8763d6231e9d" },
                { "af", "d7565aa473d63577b5f5ad87b1bb6eb187cf1b07074dd6c367b556bdea946cb17966199e6297c81f7fee210481b9ba9a2c26e4d29d810d27e60d6a29f0255759" },
                { "an", "b25a45b834fbf03331b8d58034ca6500c74a49e99b7a9328c7d1f16733822164071218e931bc105944229f7da11ab7a281fb3fd7b7f920cfbd25d19e764654f1" },
                { "ar", "41aab17adc392fd68910acdbef013b8daee923184024cbfc8fb014404a23dd7f9bc1cfd91eaab81630c27fd418c9f9c710430cd1437639f8d80a6d006028294e" },
                { "ast", "d141dbafa4a7704f6629110ded833dc28f560c7b47e77d21eaa830dffc8a4fb3ffb845c48523168d9db924aa4974806c110e23d51a62f89f673667a5c90a2081" },
                { "az", "239de1be78aa450c24c700000dd11e856ae6862b84b3f4a0cdbeca9419611bd641352a9c119dafe7486a48f79f4edc9a520b9d9d9725158dd561bcab6a2ccac1" },
                { "be", "76c94a201893d114b0a27f688cade12b81dafba24c2ed2d53caa765bc6ffa0f0b192204a4444f13419361cd30d705557d6522a811dda94ce77f650ea0a0234e7" },
                { "bg", "1765201d22921fc9018586135fc01857529502edf547741e2f7857701d11cb580c37f51cec3244202f7a0c4afb2bf78aca842da20f654296e03467ab29573e6a" },
                { "bn", "ddde56c9e4f47d0bb774bace4826168cb4f446a620d3c22bd66afbd03c4aadb972e9e29991546a396790fd2368398598e2302a187695c6a2a87877244f87e9be" },
                { "br", "e54b238f94d02f37ffcf4f5cfb077f5737af226b4d51d9123bcb1607490246749d5e7b37f4ecdbb18f05ddf25c212db4540a1e774d2a12c8b99dcfceaa99c999" },
                { "bs", "2e03740e271204013e072a33cba807db5577a9f45dedb7d12e4bf7e9acf2e838e5106068df3784ade25ef958d30be1cf0f9aa1865457ac0e26757769bf926b39" },
                { "ca", "5ddfd5a9ab81ce33c22d5da39fb4bad4e478ff965e32a9c8fe764ad91e63b92f67751d8be718f08dbd3bebf06b6aa901172716b339c3e6460690c143281c7ebb" },
                { "cak", "f1c46e9619f626b7243cd599ec42f939f8017c62568137d4465f9f765b96e2eae59d5961b3d477c8b1c06bb684c759e182c70b9387bafff09894180b8c1b4cac" },
                { "cs", "4cf95cead4fcda3bc3b6b127f8a9679ce09d739277f36e4cd47202939027b069405ebcbc0346c67e6b5f30f91d4fedbd76d862f7a636d772625a438a489be1a9" },
                { "cy", "7b8bc41f0148b5d2a82a68f6b68abcbe220ea405a43650e00605ebbed3bf00768a2a873c993182f49304a58cea6aa64a31011962b4bcf7f889a8148bff1cbb5a" },
                { "da", "b1506308cd84522507bebe695e53396ba59e10798913213b4176e2888280c0b56714a1648e016f6d746fdaa43b3b91a9bff8f461fcce34951857814c97b0f104" },
                { "de", "d2289878e2f1495e1d5d368ae8fb7e96fef197ae0d519455b1dc3fb2e01b28fb46dd3888ec9d587f2fa85a9d5dbbdc2d54b38e51abb6a21337227ebaedd8d4b8" },
                { "dsb", "17e7ec7463ff0a1ad28e2267481a42c0bb7083664724ca967678d5f459d7b8d6ef419f4ad2c6f799ded2f047429f57df3f703c8f5f2a8c733419e37ed0e3c1c9" },
                { "el", "403611b076c7d14e0ae74557077017be68371fc6df6e12bc1b650d35534564c18e2fb0116a21bea49308cf63b40ed5aeaf0581536296383230fb3f05675b2077" },
                { "en-CA", "c5083b43c7bf43c6e98486256be1225a3d718434a1eed3c623995e0a45d64ba895b3dc41b15a8d53a728f65aa28f1c0470e2e572c7c6c1e0f6241e261b7dea15" },
                { "en-GB", "658b514f61b84f21bc0942dd0b8f8b7a660cb142e8664c39d91615520ac8d46cf62abf3d57371408afab42b4fe3e6c4cdad2a0b8aedaabddcc40ebbaae30c977" },
                { "en-US", "9c06bb5adffdc4940519f314c5a616d99821d44bce93435c7a1607e58a85060758d285ac345c95a50625f4b8af6d1ea66f65bcb1d6112c7dd384b183635eb35d" },
                { "eo", "270b1a533a7c090be71b40e316bd87b3d250563ff6e498418b8b4bfcc442ea4ff7eafb47ddde1cfbed3f5747d8fdc373a8512b8127746936a924a0ad36fc4c50" },
                { "es-AR", "cecd95cf456272aa410bcd59cbed5d85fb3f361ef262600129dde71f535b95cd779b116b53d0a54d6ec7563717322bdb3dff132babe971deef0a8d5d75b04918" },
                { "es-CL", "89392bf1f76e3a445a5ece9ced9dc07586a78ccd464c9b6d1dcf7c2b1451daae15b0ba1df31d223a357776941451b20fa6f7cc794a59771e910ddfc0e69cbe55" },
                { "es-ES", "17bbde5871ffae5e70a1fcf31cffc9988c15877f86837db1dfe844e64092b893415ec93b7bf50360d540ccc1d79815a52e920817047baa93ac6c3495300b0cca" },
                { "es-MX", "6cab070642fe63ba3b14a6321b398b5f7d5dacd9e24dbf984d7fabdf2d69dd89c266cd186e0dfb18f2ecc40b1e600e0b83fa8be424bc66e43c596fce46cb053e" },
                { "et", "218aa3bddb1a2242a5c5a4ca10925f0fb775278a7d158af2b7c2711aee806fadc87c63ed04770afe5d4cce079b0f5b1708fd6dc5a7a3da4226ccc09da0760981" },
                { "eu", "b4781bd40631fc5759a596109d7cc26b15fefe643e851bb27a3c778ed38d812bf7e2594279a21a9709e805aed390dc47cf5cafca3044d41c92306b4a22fa99ea" },
                { "fa", "43022120bc8aca75fe5c9f5fdc7489c7ec6574b974ac3f262f0e1999b5ead2811683b93a1ede4c7b66ebc37aa3912cd921f1d8066329d8f4197c68b9fa35aa34" },
                { "ff", "de88b1b42d115112da628eee2c0cf06aadb66c0a729f8d047c3add74153acae0ecff1beb913232ebd93314a8949bb0e4acb8d59d273ead80618be70d6f2ad2db" },
                { "fi", "8fb540a505568f1cb38272fe1b714cf226c0c21e168dbe69f47b208659a9cff725e0fd47d1bbfdb4008b68cd48681e068ff8016f72218dd9daadd20beb49948e" },
                { "fr", "374426d9d1de028aff6b104e0c2b3183f04f60c76322fd05d5f10a43924e6ebeacd865a7aca25f26a08fa914a3144d5d14e224eeb4cfa181fc307e72951d57a7" },
                { "fy-NL", "7a65042a6a14c9707d6e95ab4160b91fdb07a82bb722f0f9040b71fe9019bf50e5df3ad60d2871ec3b56da0aac2e2e7f6186da1fb44767e529e1cfe0423ac1a0" },
                { "ga-IE", "e08a3e46d3081c614227540e69cd7866afd77ce60996270e956f2c1055f2d0317da66190020807c1a6e094e2236c38649b0f72d26225dc91455aeccbce2a0451" },
                { "gd", "6d49a0aeed2ba98e56a870902d9078b33f0749e3c8b727c87ab6a6c6d69f3f822c36fda1a91a6c04b96a193383b9fc12c4cd943a0212474fe658aed5ba494255" },
                { "gl", "c0cd1f73e6fb4afb328923496a60b3caf9a98d4a8d61c58de4b6cd16545dbc5c6f1dd669c8a1891824e2bf61e1c2c53d015145e46d1c0963286b0549f56c53a4" },
                { "gn", "38d2578bab6f156feacfe4f518ac1e1c061038eb85135429d0bc1108635fd8992c0109c90bedbd6ac8e01d5c52d87a282b6210d31d1d048915bbce3e170f6bc7" },
                { "gu-IN", "1f83bd8e32c6f12f66b2876c5439950a0ad6baa0a34ea6727197a80a320e9c4521aa9edaf56943b645618bb13e1960a389ac2053eae8d03c24cb6f7445224afc" },
                { "he", "8eaf6a99d1a26ff32bee03bc8ef91bafdaf3a08f00b2dfc9be199e87c230ce198531f45f7d62673b6918b1044180053fab5e4f301d9c43a2533aa7f6ec736571" },
                { "hi-IN", "9b1b4402938d55cfd6b2d5f695ff26382da47ef5c364fe0b10f72739a501b043544556b93531c442c95debf2072eef5719fedf113ec4abf75c6adf46b88446de" },
                { "hr", "52310cb263163dd4cb02a756a4005c1cce071161ef43e00eb176bcf61d2fed37b101b99b8f7d57b655c4090508040930326a1272b2d83a079d40f902eeab3f6b" },
                { "hsb", "389bc1f70b8ade0f94a540f5cc6140beac796c48ad487fc9bf83ef90af890b1342701064e7eaed1d08694a43b8c88cca92cf8bc9683820c6440ac470ff85c4c4" },
                { "hu", "38445aa51e14497d002abae79317d222b8179fbd843133284f4cef2c9d53162ba9c40e24a4efe255018694e90ad813a8119e86d5dac18597fb1c9c7895b20b13" },
                { "hy-AM", "f71c76b7bf9c5b4b623735e088356469bbb42ecb0feb948a5a0568cab018143f26a1c9ab94261d56d3ad25a6b0b0ec7809c28df29380d36f50bb1062167e9da0" },
                { "ia", "45259d5176dca9decdd0e87e3ca5f44e966dfdc341193be97f54685bf3cc1fa2736268f04fdaf61f999beb50257ea087cb88d47300b9a43790cc0c7e4838cdb4" },
                { "id", "c07e16410ea374034a6e7421394e9e7754031ba0254d0832aa72f99b596746ec6d196fc89dbdd51881ac5fc2d04452dc4f1b08fcb6897f8d61f39699f86d46e0" },
                { "is", "c8411528ca2189048196d5493b21d1cb62e6df3ef918e33538fa6795ab6e00b18c4d63088fcfc19409b7187020c39d968448ce347f041d4482e81510dc50f980" },
                { "it", "b24b05ec0febed7a72bf161b4dd95e6d7e6b29731e58e752ca8942cdadd2424e6d64c90a8df6e2879519d7ba63fcf261994636408765e71e74f12a168a059f7c" },
                { "ja", "0bbc3d25e31587ccc6c3a9defbcac74084a07d73af74f8429ed6cb4621f163a4917bc81032d5b93840fb3272ed46036fdfe746bc3bfd7c84ec2284c4f1a3578f" },
                { "ka", "c8e05074a8036cad4d2729b88f18405d4b8107acad235e6cac96cc8465a5d019ba53adc69a038df20a8135b63b46a6251265b2e3a7d27c6db268f2b82f474c28" },
                { "kab", "e653d9fd98c33f3cecc1ed335f3b8824367a441e325a01a42b765b67d0f93cc7a55e98def1a1a0ed2351174a6e754262230ad3fa9b5de17f6411b36721861443" },
                { "kk", "50cf1a01da6afb337d9fd6d09835b8a78475d508e83c7d07658b8e161483c865c9004c94eb9af7e6475c61ec49b94941644e224b8cfbdecec1bbd643759954b8" },
                { "km", "6cee932599f55fae6d4dd9233fe8ccce1fc09f5becc4517e75340b5bd4d36c98dcc83c7636067c5150907fbc20b86a021210cb313742a49efa880caf9f711546" },
                { "kn", "d758a4475d3b0996cde6f66b6403aa0bba3c14e44353badbb9f22f75e1407f7e480ebda8770dc8775ac42ec2c4de7657e6cbd1030a3e85d5cb407a6f589bcc3c" },
                { "ko", "4d26abccb3b408e1d3a6077d386c84721c04434d2f40a94de5505c31af68f50b774a0b64276e563330298aee34f46b4fd35cf22cf3529f6e60cf47b6b1dbb1b1" },
                { "lij", "4e92e7cf3866691e6e67f83064c73df35920bad3ac8413968748bc514d40280b55112a06dacfbb1b2b7db2c3aef6b640591b3ec9df22c802416f2a3917ffe7a8" },
                { "lt", "ece75ffad17292e0fef6b9e194047f081e140ace28c192c5fc6a239011e8b27fc28c8545ee670bd9c9c9f7debb84c3df6c97632dad13e63ecf39e28ff85d161e" },
                { "lv", "5e9d8c76d940077739e7835392bd7af08a7622d971a5cdb913d8238b7d4a0d49d3e52bff5f1e0209f9f29a08d35b197d05135d2c4591327f2cbedff7b6a9e047" },
                { "mk", "adf719e3f0fa133aeafd4b3d28c72084346d56a79793b774a83ac4f9c7fb4bd982e89bb21fba4e6efeab1bdae574ece2bc0525de860f6b65918ae3327e45336a" },
                { "mr", "283c164eb3522ba95518669664ac5764a9a5f994f8f9fd9c75f24590d58a1fc35056e81f70fd35d434a4200b0b10776ceb23015bb39e98bf2602d74afbf69e84" },
                { "ms", "ae267e325f4484acd06396852f3898f991aaa145aa13e907f8dddaa93a077d3ea29be545abb6da8de29eca082294b2f49ae598e41082c8e94fb1e1968e88e3a9" },
                { "my", "debfb0279b44c52cff0ec7638e500ca8aa0f5a4a0fa8730ca8223789b870f52fa484dc22a9276d8b315d1a10eb82e2ea5de62dd1ce41cec70c65b6c011a9109d" },
                { "nb-NO", "6ef589f191b69d6dbeed08e2e7a9071dc59ec5b5af512a9fec23cd07fc4d49bf63ac7dc0a01356c537bd02f395d4b08a08272060eb5297eb0afa354165564e63" },
                { "ne-NP", "d15a60196efc7db82f6287268084244c88b1c2993bef4a2eb1cf4a607f35a0a47046dd65a5f030d2af03d7286bb20b15e01bf3b8900fcdba1f8d6767686e4e92" },
                { "nl", "7818174b0eda917307e25c7195767b22f39f3af945b876d457ed2676db7814099327ec8104426bff7064b28c219fbc8efc02d99934d5631e406e5b06a7a834d5" },
                { "nn-NO", "e96010bd6c1a0331c2b3234f53c8da507a65dbd16e26b49976d1bb38c955ec2d2faf7ad8ed58b0302a13eeb6e6224c9b8ebb0eb579cf88500a265fb9e4a0c15d" },
                { "oc", "4c2c82796b826c318be2f172562f234fb22c5f83d424a9f91be6e5cb61941c74ee32e3e1679d0fd50bf9b68b48110e5b7c7e78c739bc57194309f128dde2b2c2" },
                { "pa-IN", "af95c809b3980e2a9fc42251e50d9ee6ca60db85f7d378e993a6f6737bc48edfb76146ee95ad24b583796f144f645e0f57205390a6c184ecd7128db9fcf49fa0" },
                { "pl", "0a58f8ecc9d9893802153384ddcb9ac7d0f6c4889dff78f0306920f2941dbaea5a4de7a30e74cd4f9a899cb2a8e53ceaa29f83b5c9cb751334b892407d0be007" },
                { "pt-BR", "2fac0a4bd90de2cc29611fc976b176383608b58b823730cf011cd4701ea1e46721c77345dedcfb3a297de32be02ee384489b21376b97f9291e31e80c630eff62" },
                { "pt-PT", "bec3535d9a41f34feba7dfa8d313a889decbbee69b75c98e349b477fcf87648cca2f6708ed88a7956d72be95084c962c5bb4861c92e9eb800d64af1604a6122a" },
                { "rm", "dca6f364970db0bb69d6c3e5fdf627e0b7e9bb08ce6a044f25bb56e500fb63f3d4bdc5fe1955c4329bdb04e47ecb1337a29a2531ef875d76b12a8c3471da740d" },
                { "ro", "5a63106f5585e11990f665b481b5520f5eeb0843c4754231f59ea2300af374b0f88a4fc7a6513e115c83c2d92c0ffef8893aa5f8a7b488a6819fa393bb549f3a" },
                { "ru", "36c666d17d02fe7549a9590e414b4fb654e54eff54dc7b4a251403c8387af6854ea083311af73cdc57c98b4c5f509f8c6bd7b75648ffeb7ef30c3fc99e757c08" },
                { "sco", "c2c14313db969f0d4097c249f96d4944daa28874978ef783729a1a8c7046629a62e12b22855016e271d3ac822ba9ba8bd72e4214e9535b7f297570bfb0bd1afd" },
                { "si", "58b498f21e7c7eea5a27ae7c7320dc642eeec72e2ec7e31cbf7490804623cb8391abdd4621cc11810d92fecbdc03ee520754ad3cfa9e64396b2ddc1c057530b6" },
                { "sk", "df936e589ac6574d9e7df39fddf6875978d552430e1d992fccc5e7bda4db7aa0abedcef08a63816a5dbdea36c17d15e1e39ed3b82b6b2ee7b298f848c20f91ce" },
                { "sl", "5f34446261d667ebee4d56c4ea2b3e2f3d7a912b8b042d971c6782a8a4c7dcfabaf8762c1421a1b817ff2938566d9626c745eb8c67a16a7d7abb15edbdf0bbb7" },
                { "son", "0977c241b55d27230a1a5c1f45f56f80918076700018b35a1d9342daa9ca915081eb6d3181705c5c7103a8cbbedf7684ec964a988a054743b66854272fa7ff1c" },
                { "sq", "a785afca829d9b37dde89611d99050bba0eba9955ca576774822600973d8cd08e77f97115005cde0580cf3ff4525d5eb6324416b18aeb21bc86860ae3b74f75f" },
                { "sr", "24e4f35191d770d675f7e1a9d4b7e51e62dbd272210bc198208c053252126440a0e3e2c59f41f9a2802d9fd1ed2a436b660f955b0dbc34353527c20631d29efd" },
                { "sv-SE", "5bfa61a3a37b6ab816fd703a5de353b23b9f87beddd3ea6cf635c04173c82eb502d3947994b1b957fc786f3300831ab45dcc319457c44bff3c5431753e9d0f96" },
                { "szl", "ad2f83c68b225dc60c64d018eba52d71eca1b7984132cbe0739e7a38aaeef6f26943c841eda93affd61f30f5cbb81cddc5e263f39b155b57e49b8d792ae6727d" },
                { "ta", "6caf50129aaf507aa2286b36667a71361eed798ea19c66b261fe4f1e7be9cd5291a946036f576bc137ec5629538e2b075a6f6d12b1edacacfe4fa5a28b7a7c50" },
                { "te", "5a6a8865dfdb7317863721e54c38abe6137e587c357ab0533e58239bebf6e1b7d1b9c6119135d322f250ea0cf6e1dd245671ef41336ae66d96c43f6eaf99629b" },
                { "th", "67365cf0dd8c8121aad2012a3a487ad4d3d8bf6d2ca9ebea4a8e64f1805b40c1d77ca15265026cacb757e98fd58d8d58b558cc663db40dda6c1a43dcddf1d85b" },
                { "tl", "64b51eb48c4ea2cea6b6b393b269a194396bb28af069d05118f0d7af62046ecd5b8604b5de02b6e55e749f56138d40d7f83d8e3a1fb4b207fb2e528474db9023" },
                { "tr", "e721545ae26ba99f79691c88c2e44c4f37f136559e1987e0ab9136a899930e53609f7df530b6f7249a077dae0fae5b8df714f289dd03701b8050454d3fe1249d" },
                { "trs", "6b4d11b28ee06f66b8f59a8654f32118e864f31598d6e3fdf3d78bc9a9f2a2f2537ad7c4c7b5b8b07a7f592ad06d9e4d17d9c4be9dd2ac871f7ec5cb9fa7d68b" },
                { "uk", "246bff9c762a10ad176c1a1cfcd7ecd46141f8b5ecd92038e1b914aaa93f75913f03d4f2d24209376fc8e68219050dade41b2b9e8887508b8f2be10dd4375579" },
                { "ur", "1e4ddc26b95de0caf6802f44a4ceca3a8abbd29711694167d881f79198ab036e57d35abef0f1f0634eabaa27fb72840376dc896522e7408c5bee096a30949d51" },
                { "uz", "cc4ba3b38489a35794b55eec63ebad3d8f95a55b9ecc4381dd12a8a2a2bdcdf381540908622544f9658879a789c093b9147211c675c300c0411e72a01eb7fc93" },
                { "vi", "25a643fc69449387be97bce985fe3c9e57fad03f398af20d1e627ac5db7735c3673030439cdcbf7325ccd74d74db89d75b523cdd28f5b54ac51a49fa6b2a934d" },
                { "xh", "ef46b0137db5596e4bc4260c86005f0c8b8c7b35d8a38aeaa0769f3e60ea26354d29b53f4a29662b51b411b0c5738a0ad97093d758c441c1dc5e71eb9096972d" },
                { "zh-CN", "0119565b31383ee9f652b1e690d16c6be835f76dd59e9e1e0735d8a85f511047f66627abdde6ea6f517c4c5ee445e75f84239dc3a687e3c2a6fa699dd03fbc44" },
                { "zh-TW", "dce4c7d94f9f9491f7c6408ef3c117941bd02b755f72dd6a8ba416938537beb40b19102c362936bf8bc6df82a5147b88e6764f00a9b009adef0316b875659299" }
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
            const string knownVersion = "91.12.0";
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
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
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
            using (var client = new System.Net.Http.HttpClient())
            {
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
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
