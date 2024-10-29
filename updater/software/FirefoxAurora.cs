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
using System.Linq;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Developer Edition (i.e. aurora channel)
    /// </summary>
    public class FirefoxAurora : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxAurora class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox Aurora
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "133.0b1";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c2019c79d7271ce71414e9dd9d42a50dccdf7fade688feb173fe5be26f3eb6271150c51ab514f972705f17383f3cecdaf669eb798ced0d417ba35a3cdea76198" },
                { "af", "e0a671616b34d8d1634aa8b03fb799f9dc88f6f4fc93f5a37d1176d90a9e1dbf1d4f6f2c574e8cc740c795302f87a0494e8bf9ccbc6e883618c56f9bc390d768" },
                { "an", "b5436247c6eba9ba7e31a93712dabc4cec995b63e3d0b6cf3616461f04bfe457cfba485a2ff30a920faf8b40678b3e4343a63145695176f643ca71eff5d4a7fb" },
                { "ar", "b7d6a80b7557c3b38cf6ea5abbb748537a4536f1caa9213c94f4de2098b357c496625dc19e11c1d210e1fa5fab5ef8dbf75d892a4bb66ebc5490209b1b0fc3e9" },
                { "ast", "e592d1bebd7d74e844c054023c7f8dff851b746d566ca0f52b514730bb60e96ea28d50a1c8a9462088065213618ff27a3714b8c73602b2be741acffbfce2310a" },
                { "az", "ed165f57755e1859f625905399861f7a89400e582806170d17bf8ddf58fbaae5b9101bc282ebc1616816b1fbf7130088a421c535a3222587daafa76871fda6ce" },
                { "be", "403df03f711791cfb2de0592bd4ccb617b24a83b7b3a2d3c9ae9d2b5ad8216876d7d8f205fc47770f53c4a1a3b5b9515016692ee58a899fa2c0c77538c361545" },
                { "bg", "b171e76f255937d58a9c31c014141e67b37f0d281729f8dd1abf7fd027b45d0bd3328f7eee2b87fd6474195b94a0e9febcd1eca9aa27ca952a0f5fead3fbef4b" },
                { "bn", "d80d2e501161156b0a10235fc292167f1b68db326ceb32a8c2649dec9e310bbc3a84166e99d1054f381c85e09172e00719b5656f88f71c748b844a70369f9649" },
                { "br", "4d1ce7f3e2a8fa15565ed45515f10e24e8ff02ab235b5759768591630048068c26771c8a4c41c52c7b236f5c9fdc832877b05910b2f41a9e0f6d063328fb0e4c" },
                { "bs", "ff3c8f0083893a46fbecb01ca716e806f3928e59d22e4280491d6146674019306ece0960c84c2db91c494e3fb78f0ccf314edb597734ca2ceb1062acedd70c49" },
                { "ca", "559b56a12de11b74200a3d2e99a8cd84d52aa64210f3bb3e5a95ac466b5c5aebcab4dfb748356643564da8478269b7dd83336672313f0681aa8feafb8a325811" },
                { "cak", "dff7857b354dd0325bd4327ece93266981403e1723a8ba0c91c5ec96fac7b4253701a7bc459224cc203e953da6de70e1ca93a517e79b14a6a196d5ebf1866d01" },
                { "cs", "ac2a5db5e438393a05cd9a996c2517a4965f51d2f489484039ccba51a45c967f882f02dccc0ec218604d75e68e7393f3b89f314b0647fb2a035f737c03bc58fd" },
                { "cy", "3282cb36328c968d59a6286293571f030114b0a0d11e626ad4b42f5e9bd0b500095d5651bd442a68df447ef4708e3c25c37ad0b147427c5a8fd25ea744f2a33e" },
                { "da", "f75e8515df81b997084f77c2d9e8e7aed156fad475389eeb789c3cee1e1c850d27494df8c066b37cf93a206c50aa1d6d342327039d749339915fbfb0e06a7328" },
                { "de", "97efc2717a7559715c198b7a720edeee15865a1f7745ab374407e3402ea60e12e31ad460ac86e342a8d98a24902ab7b65b86a6aea32db929442339b429627cac" },
                { "dsb", "d554e9cdc1fb98b82ae6aa725b6e42ea9cca1846eb9e6156bf60c80568df48d30a61fd27e3a3a3741c518cd625c3f86f92d31aff4eb7d16717c660e9e5fae6ed" },
                { "el", "21ee044c7c774c2b5cb030eb7d206f16dd57abc9ca22d1360a07cdc7037746bea8742a1cf6c5914c757abf2c74f4381a27e5624066342c1c0b882f7d311c18d5" },
                { "en-CA", "43c655411704f67578a1e56ed95e9751cf082c0f7c8bc7d7e56fde135b8610cb34e3991cd88b3939a7f24780ec5fc8d3ab320968c8e0605d35450e98186278a7" },
                { "en-GB", "8f7d14980d8192c63e2ddcbbff40174b28590675f8afb3802fa6de0f6ca9c864cd1fe5af2253f6556f8a7ade602639326df584af3c5e6cae6081e923112b9760" },
                { "en-US", "518de2db89468c7b4e5c3a8fdaa515a4163fa413e344e20f384d92058f0421b0f9a44fa3ee937f950443d560e57776e594427c3ee5b608cd2a620e6b1128aff1" },
                { "eo", "bb4ee5c798b5d649159596bdf4fd1c9c6daf1190cbe15382ccf8744f801cb0cff2fb4316ba61dd879dba6e9d2e3969574c40ab54951ab5d1b4eca0409c4db12d" },
                { "es-AR", "f549bf78820eed1c6a02afb7df12c9d32382c98ea4706581ef34d034a8e08873150ed34b0c80a1bf210590db7ebc6bc06b0c48dddfbf14f81729100dc641b8b2" },
                { "es-CL", "b86437fce00fdb46ae1dbaf5c8e28f6d2161d9285081cb81d53ccc6e8f94d20ba8dcc7bdf203fb1cb9942bf3df177f75fdad0cf339ea103fb6787632d3f8dbc0" },
                { "es-ES", "05357b65c6a159f37ad76608e389e03e0182f98f34a1a2f764bbb051f2ea49eb0bd0f64eeb24237a3b1e72fec3ecdf9b6f17427cfb85af23af337dec73804cb8" },
                { "es-MX", "09802f554e9d6c49db5c9f9b37f5833ef470feebbaef5bd68f665c32483709426ef3ac4ebee75e6dd4d05d0efd61fff41031334c8c8560aa5371fd1942eb7711" },
                { "et", "ba62999f3a24c2da9270e60a74d7aa4b34e54df65d8b9afc810eb258b37c10eaa01daf51ff6eaafb1a4d7542b894ffba1b48dc1343f3bc86292bc6d39f2e0580" },
                { "eu", "6af5db401b238e38c3cb787a96a8f601038a7393fef5177ca4a92ee9185ec0e7e7b6c5c433d1dfd59bffe91a344b3e1a979809d0f84114ce158e41a2ba4645a2" },
                { "fa", "00ede76053424ae000ec24fa373338595375519ec9a00b402a6636380b62a806865030b3645a5bcf7ff55faea11ec31262ad8888d8afe51b73c10b532345d036" },
                { "ff", "1576940afaaf92e848e89dffe2ccd30909c8b3f21b321c7ba0460d0c393f63d9deb7e5816b48862701bce2422352ab2d94642fbe5a9c82533ecd93acc8774f3e" },
                { "fi", "c07fa280510cd6b1f502173ddd8322864ab2e6985020b85f821d550c6cc18bbaab82edab384dc7cd81d5ae315c0327d67540e1e5fce3bca1ae0c65518052a146" },
                { "fr", "ec3b5c25775f1f158ac4efe6149a0f5e8ca10bdb6fcdd33b84118af76167cefff719b49f70fa58dca43197eb1d14f5a9bd47a3336c29f20ba0825f98eba6d64e" },
                { "fur", "beddfbc7fb4679118e819ae0ae9b240185c7ae171f8661f5a868c191ab21793996209a587c1f84330b0801cdcd676fc417f0e2169e5b50376face01413efdfe3" },
                { "fy-NL", "d8de47a6c9afc36338c2d1cccc95d20331a2eec28bc7b0466bfda9717920e2081e024bfb15c4f423e787e621ddcf2c707cc56c539f9385534af279df19832232" },
                { "ga-IE", "9d370dd6e109424dad3f3819637e1c5668fc6acc27462e7bd77cc4ef8dbb0ab8c6cc5ac381104a394e2f2428101175c1a2782ae84e3dd8e89b8c6932eb7e62ef" },
                { "gd", "e95ce26bda6b930e62e9410b25725b5c024955c060bab60f0fe6ac7903fbbbea0aca36074011165b73129174122acbbd96b64bc7b450edb63225cecc60e15495" },
                { "gl", "3e9531a9fe5f76502a5a467c409e61eade280cc0c0a3dd0f29b6b5a8f0e15e98b5afae78d96d6351a722b55fde2b80b9ada80ec21d5e1fc5f74b64f1a06f62c3" },
                { "gn", "1240bc3713abb1dadbf38d240254bdfa3b7f2c548bf0943b45f90f78bf45a73f3d81252929ebe859d2f398cc01553bb9233b57cdebe4b7f566e9dec2e8b1d874" },
                { "gu-IN", "9a7705f119218cf7618c63126f0d9c31d259fa51f1e5b7cf944ed2b0723a90b48084ac6aae97a0b0cc43cf61d744af1e5f6b516b719aed20a0224ace8cfe19ef" },
                { "he", "a78720b2df1c463c2caeeb4a98d722bead3ce5f1581a535cce44f4394eb3500de0ef087ac390bad93726d734aaf31d4fa787bf446cc8e7e92a051cf6d06b00be" },
                { "hi-IN", "95a52c23e68c73afae869bc79c100f74928fbf5e5a93181fea740ef77b5de06eb94739749d9f7ff8e347fd01031961c97f64cf1a73701312c8322f0d45ad4552" },
                { "hr", "e64cee1d1323fb5b2de431257b9d5c7ffed779721c7438ad0ef1e94d9fcc927e2a1c981f60ab654a328dc193917117be6dc3b7377bff448fc9ab1029c414251f" },
                { "hsb", "fe40608e13f5be1191ee8ddb9d8ed74390513272ddba4b1fd0683cf7a3c4fc4c51da7438e8b046f25062ff1f0c96fde0bafd0566deab46cb00d4b360f722d3b6" },
                { "hu", "f869033965af0456a62a34d830d802724dcdf55a0aaf5e016a48aaa2e2cd14b1e3e37ad4bfa9172538d9deed3bf31a4976a66048adcf62a93beec29df74c232b" },
                { "hy-AM", "7e450e0cd56b4ef6b773f366999dd46248c81d8798908aa7762e0644522ced4b9d763346e7379dc6e8bc72057a267fbc730755d158c9f3ec40ecceb20545b020" },
                { "ia", "4f8d5f81cd7fa87c5387cbd3824f79ae55844cb2379e77d6e41dc1510583434f12c0f1433bf97d2d6d02ba7dc882b7b14dce46620d31e469f706f60f8099579b" },
                { "id", "dcb940624a85b05ae4a6fb2bedb9326f4f47853661bb12c4ead63a9ade8a56e45b43feec860dd58553f7a462a39a25d01867e676e26bf13cd9a355d2dc50178f" },
                { "is", "7f9032b8e884aabc5ced1bbfacd3b1a10c7f74a406eec37c71df19813a9c1899f4117b135a3627d2e8d6c8b493d424241ad720b9368008b31d9de54810d87ff8" },
                { "it", "8cd91a463769a1f7bf103b900f5a7f8ec21d2867713084fa61427068f220de65ce57d03b19ae0b06d3278baa54d5493d98bd1d216095dd8fc063af162ad0f50b" },
                { "ja", "5396795580bd25178f9148327b60aac8cea16909a16b34815d42434f2e0275575fcaefca18a9329b13ad613f9c6dabc83d05fe3e3494c65ed87561ff45c76c83" },
                { "ka", "4b109b72135d9a66b46fbe8342439938adb180d85979ccc9f17e028761c5f2c2a4063e5423ca3dfff9f0dd4368a9ac391d6e40cd47321f71280f25741ca34214" },
                { "kab", "efb2baa76252701a1a5923aa5ae6768ca8de7ace8f04dbfc468bd6f3d23b4c981dec88b8ffc2d90a9b33eec2b9b2dfac5233ca717b595c82710abbc969ee61ee" },
                { "kk", "a59ea481a301bbc7483eda4f2eae4ad27ff1ebfe26aac025e162eea4eda6ab38fb6a5c5de688e66ff904754c9fcc8af60585328523577e8c99b7ec26c1ecb909" },
                { "km", "00bf73e4204d3227d47b7aa3c8bd93bf86812ec06d82e16ed2c76227a6e6216f4e49140ea5236e57c48ffd3af986fc361b12efe8c13a5ead05e21fdada6c87f4" },
                { "kn", "a04e8b2ccd3050004863d726b0a369617a9f5da40d162287f0da97b49fb9f33c0c4b6f955bd0726da216c06a58b5cd6888e1ba02863459b7bcb3d3aa2c9a55b1" },
                { "ko", "91567fff944a536ccfd1edd890891507b3cd75f87e7e86f5c4b1dddbe46adc52aae06ef9c62111542584ad2d2f7cf1444461ebdae127d38e7ecb9f618d7f6290" },
                { "lij", "d6e7b147057106a0407e6d01906065ea28e6bafc3fae14b1ef598248fb8a32660ebf8bd012646eb6d9fa44b89c5f62cceb44f2839b472340c619a9b912fe5693" },
                { "lt", "f7ffbdefcaec53c18c17b368d0ed0a07da1a7715e40bac653f7c7d1212536e9a9a549236f0e5972fa40d6f586d6500152419bd12338a1dcad26d77efe9f3a364" },
                { "lv", "805f2dbe83615ad1c5335e1230638867458c1760887fc916d62fedf70c359036d824fa40ed899059cdd8d1a388fc23225f191cf42a760de48ad033b30c7b7a26" },
                { "mk", "9e58d118cd5fb3dbdcb4280fc2e1f2cf9f4f01cbbf2c77120ecc616fb29836289ce6b8db918ab5154ba6160bfcec8927db5af9a5d098e1b805916e4acaaa178a" },
                { "mr", "82f6416d689a3d96bc45f03771c8de1d85c7997503811b0665f4af951b078853e1ec9022ba019ef055faa67db1adacea0367801791f8917a91cfda639eb9305f" },
                { "ms", "ed2dbfa39967bc4a982211a671a51e69bcfc33227fb182b1276da9616335a5a511eeee35a2422bb7c4d720666902a934c5e3e7dd0bf9b93b34a10713e860b345" },
                { "my", "af68bf5265789e48fda155ba829318dcd692c58d5d11ce5fe7f51d40120e06b708e6214e22a242475fac2b51aaf66ec9f2b79e58508c8517b3cfffc22fe3d70d" },
                { "nb-NO", "824f8e88d4e58424029f9c270ef338174e7ed0c35bc513ddf7184e8da6742f307e9e760e084aaaebe064eaca0b5f2183aa1f3130093229aa3a5f0c6cb4bb4db3" },
                { "ne-NP", "96d41b12e5ed355391a68f370e97232b8f477c71631fef445dde93d49f94c05f2a61b4436849b0432bd306ab7bd0d26c1dd8628139310a46486be8f45566c6f5" },
                { "nl", "3f779a66396bfa4e7aed6f0ea5942c30d6602f0582da034b41e171d8c56e934e5f5f7931ad869a938fdf05e7ef2a22240cc622f4b73f065ecf56543fc4af2415" },
                { "nn-NO", "9430a8f519f649da6c937cd17de8f4835a7dd57012b7d0c33dee1c9963c13873465cde8656e5b1c17b6ec15297b06c754ea10cb1164a9bd95d9a25e054a46eed" },
                { "oc", "f60e245ea09e1fddf96a2bfbbda071859a288742fdc13723ef9bbf28e5dc6343ebb4b794d69e147f9e423d4dfbccbab7cd96b54c0829071b2b13c328328e6c9b" },
                { "pa-IN", "f9c915e6e71a0a4009450cb832a60a4a20dcff9ac5d5f1e46e5b8afd3cb3ec62635b54fcdf77391c5fa82e2f9f5bc0cddee8ca8d7fb2f47b432f3726314c1f15" },
                { "pl", "c1c2b422bff4affe64879c2665a2f9234c5f97e63484dbc95a94cf1c293ec11971c514379d3494f7011a606bde261a38938207d5baa1f97f3e7b259c5039341a" },
                { "pt-BR", "ff430e7fd6fe38dc86e45e1bcbf14dbf283b6a29d37ae69593ed7498c7722d98b228a10fcac76ef5790cbb4135a9c2458714ffde12d8d1579095149f9f7c060a" },
                { "pt-PT", "ca3a4e9e3a37bb2e780e6cf643f3f4f5f6b8018355ca61f947c81c05592d25c1e39179b32f1246ebe3ee5e846bf532f48724492df61fd0a7a59765bc8dcb32d8" },
                { "rm", "0f6881d82bc0f4d764cdbce05d7a053f70b4ea54d635de7d5d9e4649a0d5c14fe37694916e34c99e059e99b9a8f33b2b6e1066bfc81ec7e8608342d315a0021e" },
                { "ro", "d8ce0cfb32cc9a6b6122d294cc5db67b5eb03ef39ee1dfae0f1644c1b420b82247b9c21ae2568ef157c0ef7c27f98271b3623d44c905df39e65569da447b6418" },
                { "ru", "f69c0b83fd28862edd8fe1525a38246a7f4c241bb28944a03809e646cdeb7be346fa1064e4b98db206b9d66b2202fe257d866d3caa07cdea8aaa8867605aa593" },
                { "sat", "7d198f9fa80e7fe4bc1a9a91b3c959b3cb962de838306b5591b046ce8e4582b426e89575fc8ee00dc5da8df454f1d098b1caeb0c1b71a785944522bb8eb9a67e" },
                { "sc", "29c67f879510d0794e1712aba8042e6c90fcf75900e85d6452fa66d5019e6da5822f9d9c1c3ac8b3ceacce68aa084e643d3897bba7670014b3e9111d1000b257" },
                { "sco", "f7e61b4e5426cf8dcfd6484fdc9840051de6492ddb4dd17e4959870934c6325848d4d31330ab11c14c14ff22248426e691b964ac5808425130986f12a828c357" },
                { "si", "e4a22a934a0d473ebd38c560b2c3bb14011b420a4f3ad4828969fcbac762b6719fbef1b5bec6a08dfcc011c914829a218e97b58e989006622aecdfab21b6566f" },
                { "sk", "3cc3565795eb55c9a2004cee6569b0bd294d4bb0d87c4199c197f3de8a5feb822a53ba70700a6960a4dddd4861962c359022d2672fcf2d0633005af1f3cbd94b" },
                { "skr", "fa2a42fa9d7159dead97aecd7f6100a168bbc71778f3a9ad3af03ad891487453158662bcd9ae11bc57ddbadb3154a374bd2e836b388d201bba05063eaeb33bd2" },
                { "sl", "36b1536a35a51c842651d3aca4366bf3059e8f91c0a792a031540ad94627fa80ae452fa2b9f7e40f6d2bc3f1e154e0ea8cec5a104bce9c09d657b2b0df2d9c2f" },
                { "son", "2f6d2f1a8b4c5b4bde1633d631a195fe49780c36a22bebf5f14b81bd59d385564a32e4425a539ec9d82ea65727d1d694b6ea8e7a8f3af24c9e0daa76dc6b6ed2" },
                { "sq", "c1cff4db927c1b7b9d3e130ec41814e61ec7ad808bdcec05bfee6037957e4afc2c3d2db987352e2ee0a9bcd3070edd42d19d0d3d76ee800a64a7a3659da634a3" },
                { "sr", "b8efa68e25e3d47372d97af927b4ffa4f07a437b83fbfac0796a6d7f2f476c9b2b7fb208784ff2e0b119ccf43b0eecbd29f1786a0fcd993af55263ebd9f0017f" },
                { "sv-SE", "14814660f49141b3a62f607f47194487a3f51742f515c6c70cba749b18fcfa2a84938c6d5a54060bb9913761ac7544a6468cd2f4d6b57a16cbcecf73dd28283c" },
                { "szl", "f86ece20c2432dba44ed92babfa87c72336199c34bd2a071497af9756395356c07cf80de91270fd69f1c0b13f366983dda2c752d369b09dce07970ba92f6fe46" },
                { "ta", "0d50e0524f3e18641cd4d349caff539289d01ee8ec3eac86714ccc47c1b3dd5c1bc0ef8b88422f27d4a7853f0e0e93e28a5f26ccaff790318a7e6cb7f55cce78" },
                { "te", "8812cc82fa21277e31a8cf4aeacf959a06e53bd670dd0bca14c6061345e05ba6f3b40230c277598c5778cab1fa18e9280efc7f456fec4f7d44f467ad80dde60b" },
                { "tg", "a6e995a92c2ac1c4c5b16e646a7d2d0fe59cc8ab9ecffc23edf6fb43769437ad140829b8046dc91dbdf55630f96bedce46ac9b4a3ff162c28c728a44b7481399" },
                { "th", "eb26f9175ca93643bcbe10988fc1020cc5954071e4fdfd53ce5f7c46239c7bd505ab4ea120c631f06fa4e6bef0cb58a5fc1b3244e3bff881ed11de025f3d0eb3" },
                { "tl", "f9c74f51df70d77f81e714d4fd59a96c060137786c6dcf128985c933913cac6f036e3c3e82feb30178663230438b41910902aed2e5c252bfd0d425355ae235ac" },
                { "tr", "99d3d67a543fc472da4d0792bac64afd4f488f3f8702da028114ffa570f2ea21dc81c57471583277528be68ffb45c045f3c45c27d16e2836293eb501e23f19cb" },
                { "trs", "6554ef19f321344781b3ddb23ffe685d576cf4a5269f330141d27bd87bc8994b568dea5262b56aec16aead0dc7cc8d9d487dae8cac1ba00d8a064cf40fb1a6fc" },
                { "uk", "fabc498e9e0f9a560fe871164d3af09fb3c53bb722cfa6a0c0c01ed2575b548b7384c3a77cc4c4c96319d24d3b4f422a5671b0387201895e5a817a5e260b85b2" },
                { "ur", "47b7154e0ea6970241e50730dd687fc95c0cce8e53331c15da2375376ad9c9e69ad776e0fdfcad85097af544f4944452746ffc8fd57eef9d812ed5e59cc8675f" },
                { "uz", "a9dd0e15cc3cf67dd6b7dc75f8c5dbb288449d95a0c87e229fd18fdc2944ffcbf7d7d28e498d002be9907818b8663146dbbfeb7bfc20f0ce00aff35849a9d79f" },
                { "vi", "24a43f778b11a52976242a2274ca0f84ea110ef6b81f2c6d8f9fb42b8c98e8be0cb4581772e3c8fc99998084e9ee608408b630a51c889f3aa3a1aea961bf3df8" },
                { "xh", "77a6238484047cd9cd38241a6eb1ba1f1c2387f49a58e6ff3de528f13241955979dc43f69ae590fe17398c0141813769ffa25b42d2a1e1e9ee6d666922d17769" },
                { "zh-CN", "0ef5b48cf4c9f865f11358cd4f08a8959e2c41b1964989901e4cb2029b9554d763d1ccf162ee30bd9cfa7c4bb8b7b497ec8cb1eb2d2aa041262125a90e79df0c" },
                { "zh-TW", "d6ecd64cae5caba5ad21d950557ad0139a1fb5dacc83006f128fa350d1079382cb24c30d9c1ae27c8f0e1efc7a5ed465df70351d5e3df89a537aee9ea821795d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f6da89b27243f7197f559ccfe652a83ebcc8b174c023280c96e9481628d9a01cf1148e962ef40cb965d81ffa20b9f4b6f526ee944d2f947199e955cb6df29bff" },
                { "af", "5d18e98006212038fba59f9cb69dd1608e67c03112b0acb7e3f7980766b04064eed7dc57239f269ca889263566b1c5a773c4049a545cc05ae1ad779c97e3a390" },
                { "an", "d5cf204ac894a7e48d22996f2d989ef7e75cbcbe80fa9aea3713aaa7996c1d622e883224f5a41d4c34fead18e1f455a3217f57c27064422a049ff01365c949fc" },
                { "ar", "b8789a20edf73840bc8dfee16bbc422d29d7a7f3be9380257bcdaf5d52890e4cefcff362434a94c1fcc2058ff3829f309d35753ba68b94a33b1b368571e472cf" },
                { "ast", "ff8b39da6321982348bac059bb30d178c4e129c008957910323f24a69a32759320e7004be4da9f29ad601b447d895d5bd325eba654918f3969037e1313c7ac3f" },
                { "az", "d17720218092cb0987580831a9d1451627fe546d6595a8b05a4466392b0229c72f60101af80c9c840c0aa0bd69bbd785deddc1b3babbc1ec9201b6227a16b53b" },
                { "be", "f16e790a5bab3e2830551d1982d38e42a029c7054e959bf0ab2fb0cf0b5625ed7001f2758b175c17071db083d41c112bdfd5a92e4835dce461ed0e05f58ee0e1" },
                { "bg", "47160cb6ace475716cc78d47604e110e68b4459792feb2ebeac05fdc10fd21bf329249a22c0b54a816925acd7e55d96f80b7aef280f3be4835185b78bb949142" },
                { "bn", "8ecd248398e8d537bcb89fb7a8b6f85bb7a019f524bc453c386397adfe69a7e5ef2c9115917e0a54afbfed0223cdb551d130fab637f3e48f1bb8de0dad2775b2" },
                { "br", "27757fb2713d3fcaabd141340af3705796d89f72fdb1e16403d21b47c200c2f10d53255184308fdca1d05e5b1f19da5232431b54f9ad1a5fc19747fac14c71d4" },
                { "bs", "3b0ee878427e59e9ef13dfebf35cc26eeb668da031d6d04a1bc4c0b9a2d19a0888614419e21e2dd4e4a3ed3177829f3464d4fa56a3dd6afcf66f91e3b729b9c4" },
                { "ca", "308f3f59ff356d08163929b3ab063a94aa88e7c736466b5d416eadca12c738a4d5a62724b99f67ef0856b0162030ebcdd490a9f3bf544dc737aa8b5d37fa7a5c" },
                { "cak", "215ecdf36f24cdd3d15ac76c2f13f51e6bb9f96f89c1b47f21a0e924203efdde454199c5639789753f802e9c3dab7c27f8fd7de06312658c5423503dd8aac25f" },
                { "cs", "866a55d96c086a8cadfd7e4ec17853b106e6c87faf3394f27d98292d7b94bfd66afc29919d9c87e949da3f94d4a635220437fbcdb6864aa3da48bd02ceef90f6" },
                { "cy", "a032222f3ebbe189a5578c79cbf505a5482325f703262c0ef721759a3c0494f40386904e4c25a6e07cb6cac6bfa2e248f9cb1316f0940242c14450de0f703e43" },
                { "da", "81c0537c9dadb426a8400e46cbe872a70fb407bd266d29b4ec8a6ac1e098a026def9f011ac81582c119b2dc5c16cefe9132c0fa269cc62107371bbd2c2f3c674" },
                { "de", "eb8eb1db81424d37e342e029e3001fc51b7c55bdb20be0591ff358561c69d048e9d250854f6658b31de4946d01df11dba4a4c40cc69978e5fed668ec38926023" },
                { "dsb", "d7e2e0817ee3d3435d909a47eaa78c448fa8b0e28d12ca57d68fd75df74789d102657302a543dad7e6be3f0238572fb5db80d2501bf3f1a9c77a1993502c463f" },
                { "el", "f8d0098872177944b4f1f6ed6df6b92cf3a13e975f49055ebc6839a0c034d6e0fa9640f499e312f45e77036fb507120c0237f9b8a5aaee5e71bb9c3fcf9f2e42" },
                { "en-CA", "3824bf5a9b3fb7b6e09ae4c3538678305e1dee7a1312eab7934d593364fffd470a2a487d659f81770bdde99cac9d77810eea681cf1706a497f6c10125ea33453" },
                { "en-GB", "507a73ccb607e44269de955ab63171cc92b1af82db48cdbc2e4e1f403360514de9cb10ae6f29be7946fdc381d69db8c110cf62207553017f3731bcd0c79807d7" },
                { "en-US", "ae870058219a81bc1512b33da6d5d3c824fb56cd5572a518d80cb91e272348d524a59154c46f7ab5534016f939b85a55d497591f8ba906d376fd4929fc505aa0" },
                { "eo", "5ef44fa88122a2f27b696d69bc3dd8f889510a3dfe6b015b73469e1be2b08f4b95b44bafc1396d45c26f9fa0008ddadeac20eb0908a4c6ebb708c49fa9c74552" },
                { "es-AR", "4c3fabb915dc3f54d299ce7c608de97eec4fcb49bac9127efa9563e2cb2ec2fe1c16e81f68da5edd4a71ad1bc04d51fe76fd5edefe4766c95608cb45865f0fbf" },
                { "es-CL", "b03f40cd6e89455360832fdc7ddbdac9f65f13330ec4d81567b27b358ee8edc149f54c7b058ab02ed73feaf61dd0b5f6e07674a25089e359d365bab3558987bf" },
                { "es-ES", "105ce8d351d8909d08076853315bae02bc5e97607c71da50b302cdf86b45e9580d7a84a0d89170ced44ffe2157984921fdac10b40ff18b740ffa141231733139" },
                { "es-MX", "4bf06821af8f049d5f5d07b0caf32d67b905e45083a8cba1ad0a02f1f6e37aa58880e295564061459d91990da42aadad240792b8118c763122b2d2d6c9f1e67a" },
                { "et", "11d8a719095c48aa0dda6ce96faa298f8fbc47c31d06c71c252bf3950c817fa3f2466358e4e8b765c032a93943094b60c2e0b872e75b3a1eac39697bb114dd60" },
                { "eu", "1acd51fb9c933fc5972a4ea5f41824249de88020e23b98edf5bce8638eeef7c0ae5987520bfe3b33609fbfb604ad744445f6ec53795c9275c33acf1a3703f630" },
                { "fa", "53ccba0da20ee7e9f0c6aa5c24d650ba001ce2f3ef51af6451dc02e6bbe170d4c0c173b35342917272d5038cc46ad1096b3f10968f530f9c975806bbadf70141" },
                { "ff", "8d558b3505f9f92fd22cd2b15583bfcee1fbd15750e7952cdbdd4aa69078d9eeff2cb67ff2bc8864f67822eb80da2b78c3572c9ce9b0ae929571a1f036743968" },
                { "fi", "0d645f9fb38dcf4bef743641c4761d2aa2b1eb3c585b799f9e72659a7e3caf046e55e1f42116dde66c8663f4ffff8bc31c638be48219cbcba6b52861508b85d8" },
                { "fr", "e95bc36893661ccf2ee754b1680ee5be6c4e63483191edfc424fbb740c58cf7e8968b5e28a92c4a9cf1bcbb3e9eaa014370ba1ec024c6449db2f5480ead75df2" },
                { "fur", "d265dd471c2c38a0469c2d02316a8b594b39dc6702eb48e29eabe7056f9d92d953066886187fa3b48e154bdb1b6799c311db8d7ba32f321b00d29ff230c6dd8d" },
                { "fy-NL", "b5c1f3ffd398bcaf83e85095a10d99fa04c47eff1dbce995d4c92b61828dca263cf932745b09c58b1cb16f09f5fdb7066147b6cfde4c2895685a9dc041893b9d" },
                { "ga-IE", "303d0b0fd2690d6c179ffce99a869b4066ae7d083b8395bd1ac02c823fcfbe2112cd47bc8465852da5b83cbdc10aff27dc5e7eefa6a12910cbefed44b0caaa54" },
                { "gd", "f172303545a8776ff5773e496bb590c31e5abd121123bb7529eee585eac7006cb112271afb3526d9c90055e4da325403fd04d54e3b288ee37c58aac9336ff533" },
                { "gl", "2db24d10d29211de35b10893fb5bc6ec9a5d9ef2e78b873e543e10c8e546a413d17eca5e29e613829aaeee491db4c6386baaba66c972c6a874de9dd8a838f60d" },
                { "gn", "a4e00c3073b998882eb83cd403778143cbc09b6df85d04a112eea8b6d8e00b38d552b39fd2d52d60c120eae12e1d9d12f681658db8497a24ad5b90d3a78befd1" },
                { "gu-IN", "8a2ae5e8f8e779a28519acbd94a0915227be5d784703817cd464d58c36ce0f139f5ebf081eb71395415de3b0b643b07ef5aa9725681e79ad08b829b721700ab5" },
                { "he", "52bdc55ad60a0b49161b3a738ed713c57c7f58dc21c3f548cc41aadc52d0e27aacd4ae32b879b87c3e764b2b08daef3df54e400b49488195889704f1a61a5ec5" },
                { "hi-IN", "8a774da39cb1b83ad41820389775510d915faa295417d9c4c389d35724252e71dfbd4f8ec24dbe530317c7e9845dc9f45fab24c878460dd4439f85819f351d96" },
                { "hr", "9f2524361a7ed4ab21fa2a635787197b99c135c1962c587df5b5156bc8d8f368e87905c4d0be05e929309c6318dd02360118f6e3c3a07392dd4b2414e542428e" },
                { "hsb", "721ea20f2159954b68a32009092c4a08a99057059cebb3653454798be53e6155be88690a0ec8954a6c67440c233fd194bff3598c9eb137424e13b5b8a826e190" },
                { "hu", "3e8f6c3c9df5266cf5add4fefb9e4410dfa84731a7a213c815e3cf3b8dc87fec9127e5b7f4d7a4e0e5f39f8c2ae262d9755ad2e7b4473bfefb261eb92e32906e" },
                { "hy-AM", "471b4abce17a2191dc0b158dff9bab14485214980d2582e75a327961bd09e21934dfcabb9af16d0f9a9de82dd009be700867f75ff2be688952826c9f5976545d" },
                { "ia", "d858b6f3d8b6ccd9c8d3748cbfae2fa8368bc80f2a325867d7e8331c64fdf682556c2057bc7c3e9871dba452fb8e90508644cc4338deb4544b86a33386d296d3" },
                { "id", "b77aaa509ce88c3d5f8ea900bb47f3b7a96e03adcec81a6e2ac6b27b55aea44502be460b0c257df2857731b3537ab65fa532d72e263cad7d9576a26a3b5569b0" },
                { "is", "43c9300cbcca6eb7e9a6167b23396f7b13d18d34fd93c1102e856e0736fffc07203e3c0e1109384cc96e7beaed520e40d34eea72020164cf0787ee52443d11f4" },
                { "it", "3f402bff174ef08025273649e50059441c1e22aab96d4cfcd998765a4fea58a67724e53af9b0a44a2e28b5d2735046669520df2f5ede5be4e5a36460cdb47943" },
                { "ja", "0df771766e054100ef6fdb76b64fd7d0d41628e71057b2365abdbab3ced2baf00c4c534be792db139f8c21a8ac8893fed3194c98180c5fec7c1e77f9a5c68fc0" },
                { "ka", "76701fb987ee48dc46e81dfaee9e92b240e11efe11f77c77a4fa9c833a6e03603069dfc37ffb9dd23989a730eaaec0d06114d113b6eb1e0c064984993e40b12d" },
                { "kab", "6b1c16e2e1428f1ce9713eeccc3926da13426519030b39e2ae452d389dba789ad768fd7bffb9170df77f24211087132a5bd0a5fd15540953f15e542e73a372e7" },
                { "kk", "50f04f33c2a6ebce05a3c8d26dc1ec5918fe71f4a25aaf7ad25b9484f16bb80dae1607bf5b95d0609e3ea5027ef69a701354d65f3d71328fae1cdebf5f055bb9" },
                { "km", "e26be5b89f4e3be5952d7b870584c11a2dcff7f010594fa1d61ee669632786c95b8fad474e5ebc41f709950b923eccfdafac6649e1183b2ccf0de2bc781b5699" },
                { "kn", "9f30b0fa1e3a2f9b210c1dfaf21d220c6bbb9390d343bd026be4b4ce81c12d7a024aed621af9d1e5bd7bcf6377367cd450a1c3d3b2e38c1adb44d0c7178fe353" },
                { "ko", "0e9418220952d901aa5617880786f7d6582813f32b8db9fa07d3a7fee06b6be4be8df3c695e4351cd76193ce8394628cb717f9d5ab7cd02b8360e97b6f648a5e" },
                { "lij", "c6b81a13d5b9bab24b3c7348dbe56389748c77df5ade10f4eec9e46de566e03c5421b597a536920274ea79d29ebe16021d3e007095a0170eddace07712deb2c1" },
                { "lt", "e94f74900af5a165e8af48256dcd07d7aea8b77d3389181f80ca2e1f400ec5b3afd28ade946a603a71593adacdb5f6b7fd7a6d2365930e2ac340fc8ba4a57eaf" },
                { "lv", "14f13c2110a319ab357329adedc47dcac4e99df81d405787ec467f6cb86826b719e70cf4715fabd8bc7fd040f06d801eb3980352f17bfa19c921ca02e6ec2608" },
                { "mk", "8e5fa866d9f5ff6859cb684078a18d348bab5f29ff0f059c69c7f4b22944cb62899a2e3ceca58f489f06cda5a2b9a0644e7c9921f69e7e3abdb64f3dfac3b63f" },
                { "mr", "808135c13c24f1ef915cdab32f6a22a5a03ba29acbffd7c43ef4acc7c1ddf0595501837b759149cc8caed557ec30396ac68bdee11d156a90e885648d2a891685" },
                { "ms", "6a3685d19a042365d3b3c75c01d21c78dcc597f69b2a859ec9fc067172bc7a86a105acab3213dfa65f5b546ac15d3028336d347cda57aed585c9b9f177a1cd2b" },
                { "my", "8c21db9d1ca11c98506a6373d6969ceb9a228fe22554e3cd468983e8fc87cf9cce66892e10b1eb17d384497921c6cbfa80af65477ffcf1e20a30ede645fd7044" },
                { "nb-NO", "3285babc49417f968e226598374d69b307b561ab1fa71013c3b163bf82c50abcc0653181539daa15ba5157ea13f71f52f3602b1c01f18ee368dea683c082c4ee" },
                { "ne-NP", "db1569b6318e89e88f1b57ebcb9fb1b9060f03b4207e620a135bffacc468158539a1e2473cdabc5accd5c2bdcab74a09b4b2a94d127aeca9b2ef29c83a6a1ad8" },
                { "nl", "0792b452f906d4db0a40604af0dbad7056a45397c0b60241e40ba74562bad6d82d71c48cebdd4c84acc7fec36da1428046e442f0cf90b5fbba7ae88d9a4cfd3b" },
                { "nn-NO", "3939179bd7367697c3c9c573952051e2a94ea3d3dc3c87b6fee703bd61a86b66e544ffe834038b549a83755cdced66406842e5d67e32b1a6e88855158adf518c" },
                { "oc", "2968c20a1320acb0a97ad70744a49a71c2968af4cb51d8b87eab48e372c21e65ddd8cb89fb75e7a008f075984a76144ae165b6dcdd4127d5ef5b29e956fc3192" },
                { "pa-IN", "f6b67c41f5fdc0851256555509350b78cf79e3353fca3dbe4af55192f2efd76db22438d3eee69d47064a86c0804bafede852429936873c8e2ff437c90f1e16af" },
                { "pl", "6371e69aff5b6a31ec949330046cfb5a10935afef96d4cb6318c37fcb311ea6933c3cbe157262428c72b93382e45afa96b3dc2fbf13c06870782e442251df825" },
                { "pt-BR", "d6b7f2cfdee157c4e79c5e8ba4120ac6f24fed1d61a8ed6e19053bcb3e50383e9599bb657be3bdf7d3b7ee4827da363d2eeb32d21dc9750e685151679bb06f73" },
                { "pt-PT", "1c900244ccd561f65e3b9df44e69f1b05192b85b537dee27a065d771363c17a6a767ab31dfb59a04b32d409b1bc97de785e59b26cd54fa081183243f69b41bcd" },
                { "rm", "0475d7e192dfc60e95020b1ef51dd99e1d80a25e0c3b56def8511dd4c64af15c843d76c9be5558dc10dd4e2672fafee6258724b42aed4b0e6074f8d767b8a522" },
                { "ro", "a86674dd9408343ae00336891f346630b9595ce3d73aa455b7cfaefc1f496deb9adf99c2dfffc65c5ab50792f8b52ec3eaa21f2085ce6d9ccc7f0c6621dc6c31" },
                { "ru", "f4b0c7b2f527e83a9966bb210016d9ed83a50b8105b04306585ad386055e9c390566c66496a6f9638ac6d063988eb9b3cf1dc45652b177d121f498acb2e0bd71" },
                { "sat", "a33bec2147def000900de7b6455adb9cb0f1e254b6cfab24493558cc597b30832967ec72a981b23c56d36e62e5cdba5c0508b272a6bd2d5933464c0a0e0dc53b" },
                { "sc", "658ce8129cd4238b76fef8622711558dbc524e51032386dbd779ef892db00059fd947f055f4952b1c9d4d2aa00215bd7b72a122954dd61062d07c38c9e1be31a" },
                { "sco", "9c645419ad6ec76097a5b8251063a99d597182fa12f6e8a8f71323908be326aefe12db47c46d4d50044c2df8f9363d9107e6cc666e64fc9e334b0193411914a8" },
                { "si", "5f3dc318b5929f1091619e81d4f86c432df0ae7b241713b89420174216b722ac7a31a39104e2852967d482dbfc98a8375ea47916e1a39abf0c640b0b5e0c4ed4" },
                { "sk", "48dddbd247a02060dd7f888e88c8fbd8bab67e76cc59dd3a989a241c31fa40ea0cc59184ff9debd54ccdb3d42a977418e5c55d76cccaa1d14b3a1206070f2ab4" },
                { "skr", "7194132964bf19d0d889fdc372fb4f0a0e19e94344caa78edc0b8636c5c9e150a28fecc2e2b5da4f05f7be0139b8b3f6fe351e6fa1829b2f44a3c1d813a6b1e3" },
                { "sl", "d8f157245d753b3338c85e6b6bfd3e80a0b1155b188e7bb486d1cfe48a10566e7f91408149af71ea167b5ca5dd20506c88503be55606c123ee44cfcc90110511" },
                { "son", "e41919e26b4ddf5f5503d5d0f702650bca6b1db3f41f4a6e1700ba5b4de258197d65a41147097c45efeadad2530cebda89dae7146d1595fcdaa3d655661f7db4" },
                { "sq", "5e53f417187fe2d01b23f9f6004181766c080a53ea474e1a76914b4cf40ff53398bdeb820cac917144650bc4dbdb2264ce3408cc731003cc72a3849870b9fe74" },
                { "sr", "adcd2d9104756707a9ad5df8af6aa7624ba6f8dc3558ea7c0a372ab8a78c0501c1c36326084abd8c73d47dcc925a98625760be4a46c13ea59b32edaa10386650" },
                { "sv-SE", "ed55f7e9cd3fc5099a5370408a96c3de891d186cb51a269b2d14b87a7c48ee6e847f4ebd2ce83ec72b3ca33e8503f098ae2ce392d5814a3fc2c63141edf3859c" },
                { "szl", "9f050565bcfbe40fbe3df00e2df5afa356a1d97db04cec49df044bbd262ca3ab304224e61657efaa97651fc42c9680a665d7ff7c002c70fda67d745a2f4632b8" },
                { "ta", "85304e646307ad767ba483e88206247013e81397a9122d3fef5b369d3d316993ccb1a3332405aef976b8f7879c6d89524bcf35244899fb201e9bd65707184667" },
                { "te", "3018864e52ea22948a726adcb02309fac5cece7ced855d1b8c4632398cc1caa756508b05a9b3b4295081767fe49b9efc2deb7bbc8dd4b219c6437a719ed2145f" },
                { "tg", "442f296b6b0b08c57e7fcd5ae0556f8f9026d3e4f20109f9ae9d583294a572e0caf31cfeab90d6130ec5b645b1d1b2baa767c62668c7768e5162d2dc2e9c7c69" },
                { "th", "e0eaf49a4ea27d7b3a5cf6891e12646e504b252c23e0462a4826fa97a691945d1eb033ecd84af59f8424becf0c88aaaa0aca8ee0f7f41474b22cba1ccc786e65" },
                { "tl", "c5c9ec31e96fafd51686aaf7631ddb54fa30c55594a2095b0b2aa86dda1765cf893f7d1fbf9240ea2ad092866748c311bbd5840673754df45f131854d122a7fb" },
                { "tr", "ee79fb9113662fe6c15e2b5e8f9eecb2abc554eab468d58c73911fd73656078cf64c7b091ac6152a58763d2e6e838ef2d3abcce57c6d495fe135346c713e4868" },
                { "trs", "4df9957c89cc41d85ec7c8d431ca8f87d7873e815209b5cd596083e6a4f9fcf5730ae38cfca493eb2ea3f9dff21bd1d709670ce2a7ca00a5da872285a6a437d2" },
                { "uk", "f7581c3c38a4f0caa5b1cfe8daf0549cba5f8887c9a1653ecd13ff09bbc580144922bdab1d693f0298872006f7039e9c121d66202fa8ce55fe071f2ec92d30a0" },
                { "ur", "55152c223b730f9638699ac4934715cb8e978ca3236a74dcf111570d258899a895e1fe40be0bd8012d189b20f7ab7d5017be32779cb744b436dd292f156cecbf" },
                { "uz", "da10cf5711b40775dcfd74886ac85fd7681484014412395461448f523cccfabd8ea78995b17bf21a854fda75f94c569fd69b580b1ab6e7d034e281178d1bad4a" },
                { "vi", "f12609e4df39f1e87ca4aab9b30fff12c7ce3e648dc87ec678454ce37344a7c167b133775a9d1094bdf3e71c0c2a70f6ab147749d62140b039e1d38eee724127" },
                { "xh", "10dcad2eba40ac72fc239641109570c4b3263bdf179e00a69aec8510ebcc484edbd34808f2c2ad701b5553fb892d2adac5ce21d82b9461b6e81b14e7d9ca64a4" },
                { "zh-CN", "6321fe003c81a2b18a021cdfcf581ac08a9e1fa19a950f5821a321c5595be8000dd2a2b9e62c9b4644c0c5504a0b06042041b83a74378cc83672a48150937313" },
                { "zh-TW", "1d4f284728d8add5f6d8bac92f0ebc2f00cbf3fd6937b7c7fb44e25344a8e718138914d7daecaa0d9caef7e7520e13ef7518cd86b15cce13c88a836f22f4f8e8" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            return knownChecksums32Bit().Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                return null;
            }

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            var versions = new List<QuartetAurora>();
            var regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
            MatchCollection matches = regEx.Matches(htmlContent);
            foreach (Match match in matches)
            {
                if (match.Success)
                {
                    versions.Add(new QuartetAurora(match.Groups[1].Value));
                }
            } // foreach
            versions.Sort();
            if (versions.Count > 0)
            {
                return versions[^1].full();
            }
            else
                return null;
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                var client = HttpClientProvider.Provide();
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
                    if (newerVersion == currentVersion)
                    {
                        checksumsText = sha512SumsContent;
                    }
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer"
                        + " version of Firefox Developer Edition (" + languageCode + "): " + ex.Message);
                    return null;
                }
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private static void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32-bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64-bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
                    }
                }
            }
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32-bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64-bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
