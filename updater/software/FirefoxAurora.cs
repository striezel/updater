/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "121.0b3";

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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/121.0b3/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "9caebd0987c5d49e72b45f8fe6acb9ec16ecf6efc582c6b049dba8e80f1fb3cdcdd94b3a87224bf99d21d95abc9c9bef4d61ed8d1311b8ea474e88f26e2935ab" },
                { "af", "6b648fcf581b31b9d2ed38a7391e7ec4366f8632a7f02e7fd0fbdbd96e45ff08f0f20a592248f02db743f006072abed2180bb9baf30e5153dfc53608df0386d7" },
                { "an", "e1448d010e7adccd6430a94ed56ec745372e950665cb68203e4ec733f33374839d1bf0676419042277bfe30e828c15f527d757bfef0291407378774231102487" },
                { "ar", "54ae8512295b2712dc30bb934898759463fe6515fe7f6ea92443062a9c3a3a1c42f58e9c22bc183c7608bf2074fb1d805f0d6fcfad0c41296bbefd3ad5e8c865" },
                { "ast", "d549d39ff9f330a4816e9365abe73171831ceaaf1c978be2f57c326b445ebc43fc8278ba015bc21dda24d3e7251b1949d6ed6fb6054e439b345088d42446c43c" },
                { "az", "b8f6f24e90d750f57c2927cd8bb581514d69ea3c021628aa39d05c0d650ed91edae90abae36cdee3349770bfe352ad64e6b2d6773443c5d5663bcfd87290074c" },
                { "be", "68c8f54955ed30d3d78f2d9aa6b826b702dd77bad9f9352c3e1655c6e65ab74a883ddd1171e0c0674cfdfc45c5abde7200e3226cc61d68a95945ad94bd13c107" },
                { "bg", "022df09047b1eaa91a9adcb9677af8d53f92518b68e9f3992d83ece11be2222049c5e473a67ab9fd96bb91a06485a1613c008eacbc8384e0788b77a7b4807759" },
                { "bn", "406b4cdf655d2d9bbf1891c0ad2f7ace88a8555f3917796871ba2ffae5d4785cb0d250fdfd600b9e04634aec9642282572dcfee66b8e5b5dd433f15356084f04" },
                { "br", "1696a7fbad2efd35405806947ded1c18b27d8d801835930567d4204f6bfaceee0c48d2842464e885df0b6682f4b9ed8924aa48d481db9774d94786e8ad4580f7" },
                { "bs", "afdf44cda99292cce500c6e4c224763d1232254325d91e4b543aadb9501abfdd7a8eca4e4377fff58b99713deb007bdec4468359ba127dec68708df4e3f97484" },
                { "ca", "70af88ab8c70a7d3a006ba52bc4c3b664881f1bbae3791f20739039be93df66b2c48dcf8658d1c89e981cd3d9d2b908f71fb1eea417013ea8ac6fe81b5c671d4" },
                { "cak", "b87ed4c30fadf4edbc9693ceed1f0ef18e5b4f6716a289a8b38a7587a95adcba95c2cccb42f7aeb9155998295356abc043ddbfcb04f67ad60ba1756c951e55ea" },
                { "cs", "a94ecda70d5b769ba2d53fd17dd2a482284beacc9256c23f66be075c82ec7f371404e6cd3530f0c0136483dcde36e967e6142970222c6609bf3b4eeade0aa238" },
                { "cy", "e2d868893531856951d4b06d953f0a13941b086ba6f5872237c10ac22286b955386af5683376bef97a0a9d34f49a75d967e2336aa2fd1bf915f290593c4f359d" },
                { "da", "51e65e4c541fefc24882c21462658c5bb9ce11bea70210a5a11a240ea39432e918feb28710b51a650b211fb8a8b7cfd9405cf9588981a06b34efd5a756f62b89" },
                { "de", "c867b60e7da14272a3ab950b5b5efbecfc32beb204d449af01830e22a1f8246e1808b36e83114bd0f5a60d1628fcae0c27164e3d18bbb8850b41c21bdd907969" },
                { "dsb", "bed66d54757557b460753200e3b4f6eeffad778e3ef91f29b874c7ad966e815103a3e88d13db5e0fef0105db4b1f6643992314ceba4e59f9a1a26e413026ba93" },
                { "el", "b96b9cdbb58f9ae2c62872a863ab1c6362d79c8838b71a3ab6d8a8654b03849da5b8b4e8481173edae011ff454f01ddf7742b8fc2960a1397c8ea3b3d8107126" },
                { "en-CA", "f24c4dc8788e431063c23689df7ac324e6a7ac7c75015bb861ed0eca8253c3a90366a674339b1eb3ad8ec8273d61d9b71bae0b4fb9edd83937b20af7d5cb5121" },
                { "en-GB", "e22dd5d3f0dbd08cd31073ee03cc3cc1dd020b734a5c129120791336f7d69d2ea65e3f8de1e115ae6465bd10dff843897da6fdc5802e4f9986f69296c136eac3" },
                { "en-US", "404b83c59d208641fcd6a017210c8f9d019c0af383f75a40751319fd061abd486496afbf7821782027b8215970bb7d2eddc15de8b2a614b2a2a1a5967823ffc4" },
                { "eo", "4a42cb789569438da56ff8c3a70295b9f226be685b6cf3aa16f8c66c38ec2f8bf06bc700888cd4c458a907f989b7bcea23c381e99602e67ebcfafa956a951e0e" },
                { "es-AR", "2e15065d9ef902ed52317700a9c43a58e8b46ccc6f04ead4a04272b4ef76c326dccb00946cb01ab522a209ac8f408f70e03ba51937e493160e252d85668ae6c4" },
                { "es-CL", "2e5a56b2e1c4fa043b7a2b3518aa7079d199b9cbf7828a367cf29bff14add7bd9354b447e0494afe5a9d1159ed169a8153df4be79814911b0b8827e635684766" },
                { "es-ES", "c9684bf3762c1dcd6b707c94842234cb9589dcaf2b597a8ab590a540845d5ba15cfc4380fb9dc58e16abaad063c15c732dc9a02c1d485f9dcfbe5eb5392f4152" },
                { "es-MX", "6e7375bab08c288130e704c4c0144ce34498d7f846bf719327d920fed025a63c92ecab8ef86234cdc8112f48b3c77df61653313177d5b4fa1763a1f1d4169b18" },
                { "et", "132c3347b3e32512a7726477f0bac4ad6ed901a0a70ceaf4e5897626944cde6e767765d3fb5c13a2fce6d014bbd0d532eeb480b808466783283b4de7931d1008" },
                { "eu", "6231d8f7efaffac84568f7975914389f24e6140c66c8a41f1062237ec3cdad292ee31631cb0544440ef5bb3895a312b5d2f15df1b2b98a82514361d4d5771a50" },
                { "fa", "4660bf1675e1e187ad1776c81400e714baf6ce31173f430a31530a950d9a766a24c725ad79ff31886d715bffce0d1246c7d7c3216c2fee215551d2adc2c3d713" },
                { "ff", "1e4a2b45b7d82f0714afb6536124c1055c0331aa8fd7fc75c70dcfed0bb113be43eeabef1958e4a35efb982c1b5d70a22d92a16d8d6e023cb81b1b256ccab9db" },
                { "fi", "5b097d703e87c5d08d1449d65eabcb442449e38157540a611d1ad33508a295436bb982e3e9359d74bfd5dbf97b8cfda040814d11064de98ea6a34264520edc68" },
                { "fr", "2e3f8c9ec587fbddc487ab1044550280b5f315df110a223cd4764789f43591d6db843263145cc8951774e0d330c9eb0323df74f699adc902ef9fcd6a3754994e" },
                { "fur", "750e0ce8d9c2031b5caf8edd6dded1586fc30c6df009f785780bd70cbeaba6d00774bc34d3f4bb2ad0393f180724e9f601832e411e74d4bce54d8d7d546b8dee" },
                { "fy-NL", "54cce5ce3c36de8532cf69683aaa0ae7bba8525a309905728ee6fb80a92b1d32c2d057c071190095bc68962ea87ff644709d74faa7507a34cec45f4f1665aa60" },
                { "ga-IE", "1f299a6160c14179a735af52b1cf4334d9322e2789b0a90c65392b8b5c5ace14483db4aa10df0be6da94a9b21a35f78ad68529742c14d20b54721b30dc548e2a" },
                { "gd", "8b74cbfaf194358340cd82315fa60deba5bd938e55e5ea1d87238ea8798515a303fdda2a7a2d87d1ac10f923defb6a6816573d37e6784c277691143785ad2312" },
                { "gl", "afa5a5fb535fdaf979789537d1dd146e19ee6cc19cc3dec0f1c2d88bccd52002aaddb3414308c7f0e88f677ad15d06819375080f3d2c1f70f3c2b72dff523656" },
                { "gn", "3b81029738a88454b0ca89a1c203f7651b241c274777b6df43818550d5d61d84dfc1b8d0c684056e46f949e7377ffb7725baca25315e3979ff4b96c2ecb8b205" },
                { "gu-IN", "de3d0578153fc72e86173d5b952bd9c78233757cd7bb7ea72273cc581dd8c825cafd05695132829234ec06da039849b8af1c51fa982fa0589f06a72cc54e724e" },
                { "he", "34cfa4d122d22fac49b482e19ea46c69727d04669d9e8c060712b27a0ff5852448bdb59ad9dc804d8170af4a6e28a1372a5cde9e1ef5b1139511f71b7bfe7d50" },
                { "hi-IN", "438a547f12fe9f2006e3ac8fde04fd93484db2417961404c87e58bd1c97c21ceabd8a1ff9b9718f0c80f2b70a25ec45de49aff5dd083399470a7fccf204e717b" },
                { "hr", "3cf8c9e27eae06ed432a592cfc7e88ec7bfdbaf6ff33c34e2fbbf802ea7c0a7999c65bf16593534177d3106d8de007cfe1cf7d5a92707501885a77e584feb72b" },
                { "hsb", "581975751dd82f666a7a9a9646d99a8ffa2b1de1dd3321c8f700b051e4af4935750c10088ea370d7c0d5335cc91dc7e50025990c0d45b0463700d0afa0b03a57" },
                { "hu", "1526254c4c7615504636f728b8059e7e5f9096c074f845dca026a4df6a7e472d00460fca4acad26bc55b20c1aabc27364d067771f27bc3c295ddc2d2f0fdf81e" },
                { "hy-AM", "4a12e67276e12d451cf20514b06f2f2008ee93c3510f0cf7f45af54eae4591489482309e730449f8a615019b1e80010bc30f116d122ddbcabd292970e89edf65" },
                { "ia", "8d111f1b5c35c7b86f7e3c6ee46cb374d08036791d23a3206d2cd26d58125ad087715be800646aadee655f63efda398e32bf6fa3e8fc7a57af8061ee88882e04" },
                { "id", "f84d19fd60f48af506a405754362f898471c36120c4a74fb3d3bdab65481a3c529baa182dbdb92dae2ec67c63c2302182eade2618dcca22525600ad2cb6b6eef" },
                { "is", "3d269cba8a17be51fcca3b6e0c371f830810d30282c292e7b61357c712af9a780526e0b899b44906b4e771cd4f2a7560b60df5911fe73c25c6f36cdbe6dbc594" },
                { "it", "ad17ab5e95942cf00aca2582423e7d0f9d3eb4c639c6e091a8e7d8bd44cc03ff25ab09b3254feb594067195bd420e0144d3e48ea7dd2f774f4f89eb3233ce74c" },
                { "ja", "ecefbc2618fdc43070f782eee0bb743e63ac4a0aafdfab000df54dbd3417cefc8079ba9d7791355a98f62498544b23460f39e6b36890f7d9ac05f8ae2fe8e675" },
                { "ka", "cec3508d26224626f97d079e5e227edbb5feedc784c934fa77ce352b3e8168c302d5e11a15a82fba93edaad78f36e5b557a1cf22c973f5c8e0643ec5b7fe309f" },
                { "kab", "08f2f74b82f12d0cf052a60ed13a272632ef8e5522754f183f8cdbe220f398c928cd37d7d6a2d22c194ebcc5921063a1ba66f357642de733ca81b24fb05a7dae" },
                { "kk", "b30040d719a6685cf9b4b7c080dc37f25e89b25801fc1545931c4b04aeb61e5868cbc2c51d78019dea578b80a884e7be1c790439b8a5cdf5e51bf916bda3e057" },
                { "km", "403829b0df9923b726f41c2d55f9d4b3e89d7e6b28f22d73a55a69da2967787368143e7b0c4aa291c268b08340f7fcf792fa6e0515ab62325eaa9ad9320058f6" },
                { "kn", "f7f56f1ca08a9d755f8e44fa8ffda670d2e3e8adf998a58995eed72b445a1455f9a3042dc966df4cbbaa43909e5fb0248e14380f5ee92bc1af2b2688948ce5c7" },
                { "ko", "8caa896b13da336bf8cea957dacb0dbee18ebd8cd624ae39b13053dffe67d0baef91dc9466906381fa73812f0474a0fc2a30344ee7c00e8fcdd2c3b983229c98" },
                { "lij", "a45acc4900179320852533e8b6f6ba7ad60dddee0ce9124510b735620ac2edb3a1cc71f4ec38dbeaeb5a3e9e706986e6697727678ace25f0cfb3f0680b7dc981" },
                { "lt", "1c7c71c17b5a0a05dc4f87301e86373d8e15b6f2ffbbc36a4ffc8f7442b4ae773792f9217a4d2bf5112052cdd2ccdb38ed654e52ba6aa74c76f72ee7f8d96b15" },
                { "lv", "7cd5f5e2e36b00fc5a59e3386d949879f9ba837d5130c1221486433ec0917a02a23e8e261c42d87905b43af9a110e4ceb86566fee55e805dda09e7a0889e9fbb" },
                { "mk", "c132e20e2ed1849be744c36fa6de31ea95f334ac1448e0eeeffa78d15a59347be8a723d1c762977a30b29f155942d60f2a9c5f4bb73d04b7fbcf457fcb9a9ae0" },
                { "mr", "4a9d1a8bc552f8c95592b31b8b06e0c97b7ecaf1546104814c60a8e294adeed88fcc80c53a0f9706a2ab326c4a9136db5caf0c323ba2e50e61c303fbed6e5afd" },
                { "ms", "c47f73d88bafb9e94a4a7933ded8ef54759f41246bd7008c23e12a27059a5da0a3a9b8495f60661c0f8a97cc3e3a663447d4cef39d301ac2b32c6974bfc38974" },
                { "my", "98246509671ca4580722648caa2ef46fc078fc96973a36acea48440d22dc3d81abe475a58456bb0a92b786eef6c176c9f0b7749899fb2a6108c0577ae2a34ee4" },
                { "nb-NO", "1be91e763a3ccd8263c141f2203c6d1fa619448e2739b7df6e5eca13c1c9a126a37b7a1a3545375d636fae769e5933c995689b4b35395d4c00e96ab92f9bbf94" },
                { "ne-NP", "37c549aed268c557b6cee45e9c550c961302e629ed2bbb4e84da6a23fd8fa911b334ba0c8fe5ccf742475fe433a1e14412f713f62d74cee6171ff6c11b235938" },
                { "nl", "77ef4ff9b1f0990901820158c06a44a695acd880cc082ef7ff1ce3dc7bba91914dcb9d1297c79cc94af50494e68df14369299a0a63878f38de393561ff670639" },
                { "nn-NO", "e27c0bbcfae9df2bdeb2f7ecc35acc93bef6dc5d6d8dba9c6d4773ef3d3c54d977d2b0f098c39ec50ec68d23b67bbc61fff29f63d441297a35c3d5b1553aa557" },
                { "oc", "0d29cccfa5b52d06c1058b84b9b4e734ffb3d6a6f8611e42b246211db0fd2448e8bf0e3454aa3acd59cd41504155366243147802ac288c82fabc508edbbe2c9f" },
                { "pa-IN", "23925e9fe9410d2d57b87c25ed4e5ed2e95831da6ac2a1dc95bc4b74de728c611c2bd34e31762814126edf665598184c2eeb3cfa3881e1eb70ad8c04bf8f5133" },
                { "pl", "081ce967d99b1816c5dcfaf7dc8e4e930e1a7f89f7bfa29790f0bb0647b08f72abdf75ea035b67a1e0da7ae584c31f98a0213c755788080c9c2ad2b9ed8b4ce1" },
                { "pt-BR", "d55d48a8be158953342d5cd46853eaf32e99b0796c043bcea820bbc1c7cf4ca181b6f282c6720f2360f7605d3949bc7e1d87adc3b6653612f9b7c64ca1016bd9" },
                { "pt-PT", "f26fa65dfc567a25c8aa7a53cd04062e9f3ebf31975e3f634869538dd81f01f00fc3684478fdeeeeee2db4d7f3a468189cab3cdfa734520c90a57e413c7dc7ba" },
                { "rm", "afd5ea5b2ebf33fdb81752d8f40b6affb6e9c21b22e210582312e9aa47c49d1cb3d6c4119887aceebc1ffd74da44a3cdba29b6698bbb0ff9d65a8de9357228ca" },
                { "ro", "2e6e28c5599735bafb727674d8d6f08ed61315848d21b421eb77a5b072ce3ba3a27f0a09c78c851c26884eba3afea3321c2361851bd6ac1a7ff1a8cb18942278" },
                { "ru", "912dbb93491520ac63e97c18b23c02b572d5da24afb94acb9957cc3957e483a4ef298f5275c9eaded482f4c7abc76d5f3fe92d9991b6f8395129efca1f24386f" },
                { "sat", "077e610e554293f44342db24a0ab709731e84ed5547d7ffe7bb10a9a0042b354c83190dc80b2211e53a5a4a990fdb94718bfc8aa8873da5efa8b23a83bc673e6" },
                { "sc", "f2242864be3f91f4eed9e1756588b3b0521a74c9f1c6dee36ef5627cd13d7efaddb04d48b101001b92f73ffcedf0090e21c03cc0a2c571c3c1682d57849deb99" },
                { "sco", "7b21455aa5f8c587b3398e6cb08ff8717a25337f733fb0ed5747a55a971f20b8525cf1ae86ce67ab7dd73605290b07b4edb281f045c7d5809e3fb61c935c128d" },
                { "si", "f190d26a62fa17eba8aef64395fa848d6bf730a6fc26a4578f0b2410d2c5c77a25b79e418bc08eec60b6348a7f9b043cd1e8338ccd0e6864bc675214af48d1d5" },
                { "sk", "db1f59a785fea0fa559e34f5759b902bfab784681a2e699db4a0cf64d72628ecc1b34fc03286c889003db99895e12d188c21bd9776376f508baef58bcd97b451" },
                { "sl", "8b6dc6056b777ffc3689081f4023ec5c986e7eed02f96e208118fcfd4770bc5c7c8672e48eb125bb160977d21d2be43634530b36d1e138e14cdf77c0c3e27e3b" },
                { "son", "9dd9e18fdfe63bf1a15a97f79615a880a9cd7009964f419bc6ad3112cb8358756369919540a7ffb072037befcc6f7c282dc466fa2ada1e67570adbe332d88b7a" },
                { "sq", "9440154cfcb91085eecfa67f73c52bf4eaa8017f26e7b0b56ffa6f1d33a1748c9e4baf6f62652593f3ddd9953daaf1330027ea1ebcdb752fc241e58d24108d52" },
                { "sr", "c3dd3ebdd6a6409b88b81f1e0ff05ae1b0620016e6120882204a476097b22fa8ac46cb16c863efa8d82e23f7765101f5841d1f5022bc7f53c3d98b8a955d5495" },
                { "sv-SE", "7597c7114633aafdaf7197579c9fae99a657bc2681cd5e2b874a3f756cc298af3d7d61903b2a7ccfebc14ce38d5801ebe4dcdda3d805fae09ab435995a12b2a3" },
                { "szl", "80271ad637b0ef49c94717b425c57c7c92aae323894ae15b9091079f593aadd81ba4d3a74f0c6fa84892dcd04986d0d1202d81d1767b004a4603b0fc1282034a" },
                { "ta", "4c186b4741d02fa07ba7a71dcdbafcfaf164ec357964b5b2529ee785e68ace92848e1ae92a4c5e16f9b8f948c063d38ced757eb00f79ba2919db09f19763f252" },
                { "te", "6ba8426af64d343b25177b9f718d44539ddb79244d608807bd71a98a5b18d250cd1232b7d3052bd5706a2d69d701329346e1e65e5ff52d52f18d287c2dc4f918" },
                { "tg", "92aec10a3ae5b5b8f07b523e946622160193af7afca25e1bed3e30475a5797100e90af2de32939b9363bb73d3e0fb6ef30ef634d5a9cdc57bbdc42e32989a649" },
                { "th", "5e665b4619f1b1b553a4b0c908b7da10e2e2e4234e4f1325ca0e9e40491847adb8b18057cfbff4d93d3bff9b36824d4109344ab9ed7d8ace901d0d0e52da6010" },
                { "tl", "fa0ed47046c8e469f0dfe985f000723a3c1f2b3e33b5eed0e3c367e8e9d3f913119a521321453d2dcb4027829c4ec825b94a6f5e585eee5d9a2481b8e87d7688" },
                { "tr", "0efa23fe35f3e487ece02515ad42da364cc669b447130afb6073dec1746ce13c839e76ce6c8ea9d744af7c0a1d72e493df6dc347f0ea59cdb6f05e5145cb7e8b" },
                { "trs", "2fa539ba1af09b58f44e35681fd7e9be8dd79afd2509150d583e000a018626ecf37d5fca332b4eef0f1855eccf83db56693d5002f64390ba9de95e62b2647b23" },
                { "uk", "0f3907cd3e392b309d96255fbeac440d73ff2455761e7cbedd2e8fa974cc4aefbd2780c502aec20e2b57634f6088a307a6b956b34ec7fef5e2a186fe8c1bb2b8" },
                { "ur", "da1798f1ab73eea3c79b9ea950e954c82bad2b8490a7412dca3bcb2e3bdd69bf56ed7cf978336de56be44e00ff3d819862580184dd3e3941227c86383ff85318" },
                { "uz", "b694bcaeb749b8ab21056a0480f9daf7ce1e59aae71c1ceb3751fcd846e6da407592d69301d3b6a20b481a888a44b5bd9f86a26f9c9633adef8d6dec5a7d7d82" },
                { "vi", "2996336eadeef4217b90ecf6268e47fc5badc02c8e957f34c8da16dc7ecab6cdcec09fc75ead08c2a4ed9b4c9fde3e042b5e260d194fd7e1f81cf23f67c3b48d" },
                { "xh", "f15ab9a3d8a26931f72963eae00684fe7736692d933d308104465fcb35878bf49b51300f56f4462723f83e2f65bf7c136c59077d09fbd021e5a6724ae954d739" },
                { "zh-CN", "6ac4a3fe13680368856ae4aeee734870fad003c27ee82be85995ba4a394b994d931971992f34903d7900c57f847f10970a6667df65c87104a9772575444d63bf" },
                { "zh-TW", "c5836233167673b72e2c2c3d636c46b74dde8437a612ed851077504f2c0d892f58ebb4522d28703d636c6c70bfd2f54fc74e25434af25bfefcd751b4632c3252" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/121.0b3/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "dc759a737b8d56ff5944a33c735d26439989c7507fcf5b9bb35bbffcca0ffb203beb56035299cb215009f8f53e5cb1b4619160e1b9549de3e76d5cec9bf48d14" },
                { "af", "907344dbc0990497be99d74769749e3eba4894873f225217697a13d479e19df015642f7ac005af45b2c7b3db3637fb720d4d7ba5a2024eafc36ab845a13050ab" },
                { "an", "97ccd4aaa9623be5067479e6b0176f01d3bcc2621734451b24f35161567d08587af024fe89bc40b8e5fb4e51581a0de1fed80e74571ca1a33a9c63c1b2a8b84f" },
                { "ar", "924bac2c368d392aa36305d59222308b40f00933664868a8410a86af168f1a7ab8b5e5d1ab0dec0ebf9f47adaf857dc97426749f18e258f9e881212c69da1f2c" },
                { "ast", "1de6f154dbe5c3b85841a6551078b8c32dfd7d7458ab0049e6f67e6b4266098b046ab09dc7be53a71b499670f7e526308e40c5a032bcb8b5b908c6b41252744f" },
                { "az", "0237b0438b2358b307d0ec122f37ecdfe2ea0252a8589ad03903d92fd36de5c54a181ef857abde24e4f0c2914f9997d057263fa3388e93a0f00dca011be08014" },
                { "be", "1bd53817c97becc9ec15c136052a83394599a33c0b36a86923652aa95322718b7558a92ed5e8c3560c45384a7b029c6ac3aff3ab453892e5f459d1816b276d94" },
                { "bg", "f97bdc094b7bfc1baa97eed9317e037fb8b764c104791aeca93fad02888da61ad51ba233e72a072b464b9eec6c7a5a870432f11925558b2c5637b60b19bf943f" },
                { "bn", "979a82dd88dcc91489fb32db00f27bcfcf4c25445e5fc95f3e4dab8f61174a7408a1a4cd25a14f42b1e7b673ca0fd2a4922da3d6ec7b6ef75ee08ee6db5b7d52" },
                { "br", "d8048a6f4a394d245bc37ccdb7fa5a4b319226d2d8bc7ea583e2a629cf966894b9fa240e24bc346c46b7b8201314aaf96d19f8080e0c7e7e15ebb3a5ba66539c" },
                { "bs", "5929c01adf4edae9bf5c713417e41ad6500b655b29cc1526de61ed3f5b4b4bc5320bc28b70bb3d20cce6fb011dbbfeb51d408d98a4e07db40077137507101072" },
                { "ca", "dfce5b33fa7f629da02e9b914f4d92cff47616f7dff8b1f93b66d69235e35e328adc974877bb60c23bd44a67ee801ca8631eab4af6ded8cb03d9716e15b02dd1" },
                { "cak", "550bf4429bab47f4f98655525c08b1bce4bba53ea4ce5bb1f7d7a7aefd21db8f5caa01dadeb861e7fc90788ea0ef8f0b0bcf9f93128c36c8d0516ceb593ef122" },
                { "cs", "48d6c8a06601df8381f09685350e150e22323e5ef7945bde9c49336e95a3e04cb132746f98e99acfaeec50b4502282898ef9477b69cf538b61e913ebff3465c4" },
                { "cy", "9fef34439c84ccaacf905ef6c143dfec971d73488e674ef30ec614539c2cb939afa46f5555d7ae966655c2b564535f5478714c240dfc0337d9f74179e2615116" },
                { "da", "1688676f6a65ca53976e410067955d6e2c9954be7b4109f8997470df31eb0bc73bc88ee90886dc532cc60fb0544bf89c881b654d6b60af975d3bfd18cc61de7b" },
                { "de", "913075d7fb8e7a32dd97aed0e9b4ff6eba0f85b9c13c594810276257874b56366fc5fc8fb84276bfb2fcaa1d4b1fcdfd204875a659599557ea28583be1b84c89" },
                { "dsb", "229aaab929344b54a250f789e387accab54faf0ee856bc93a567f58d4d3d108f3c3802e27b14cf1e7970b61f7f0e8a7d43f5c5584cbb59d353a302472d239e40" },
                { "el", "908b0ce4ef3f620f10701236d2b17d4f15326e640812f8aaef7122813548d95e31ff982d28b6d044e64bdd1301cc5aa98211f7cfbbfb6303260d169dea0dfd09" },
                { "en-CA", "16b3dfcc561776c108606474c205c59f0a972e4481f497c0269acb6b6efa50aa61fe35099427029063861ecb8758d2560d0ddfb964eb0704c95d3009d78cd2ed" },
                { "en-GB", "3aa437a7829bae9ee06dee227fec69b9a479c23cfd2b3ca99b8c6cbff79836791953a10ec541adb72c466d2a6028e4689b6fbaed34849aed8ef1d77d484052d1" },
                { "en-US", "bee94090f0af9f240631f429866c0c4cf674091321ff6ecee1bb9609bc5ece51e250bb802db79bca9773d10b0eb386266be4a4e290088ec83e8215a5e34d31ad" },
                { "eo", "ffb29d4ce11b3ce0ab4932dd2bdcf716c08a04afbdb92fb4e1b099e7d8d1b31dd99f2ef9507455bb1b52f20d37ae813ee29a2fb976755296896099e5f0d06c2b" },
                { "es-AR", "0fad5c15d7a37686551cc90b0ab07d67c7ba3229234d999130a2606abb4a02a7b41e17dbd4238b955e7c6d4a669f67c78d36acf5a97d57f0258d40b48a8523a8" },
                { "es-CL", "ac4b007a8d7ca6d40aede0d4c097f246b5d769e4153e584d33ae353ecdea570d5c5e735f04fbcf9f54e8b21c970a2e605f1fd10de5b66b026fe3c4c4a7f33818" },
                { "es-ES", "a2d9e51d59255614830eb09a2de979a51a46bd4a0489f7178b9f3e1423a9c249d6a9da2adcf0a8025f21fa7c2dc57992e67274e9667987b1d631ffd786ed5294" },
                { "es-MX", "7321e4096002c9159e6f91dc46af908b16bb959d06828504c7edfa0a7090cbd3866ae0f9a41a996476d852f672c6f3af725b6e9d1fcdf32528773deef03a9d82" },
                { "et", "5398b74c9e0720615c343cc02933cdfbc442d2e337bd70ebb51afefd090aaa09b88da54fd37cadacc32d75be2c54b3b3a42ed7b532b28d17fdcb9b20384c5e2c" },
                { "eu", "8aac83d343b0c46e83a2cd84ac6827123309be8502eaf9b2ece4884cd4a7acaa40cb31751f3c2a7ca1d8289f8d4337e5fd9fc6a61605cb06ec790833616a442f" },
                { "fa", "e67428a2cfeaaa25c5dd138f1646134c38ca16a2ff8b9983447f1bcea3aaf3b74d0aa3f3c82c926ebc7b8b07af5a6c25c06f5aac516cc22ec4e5daacf7624cf4" },
                { "ff", "a36ef4b62f37e3c40d80d635c33cf1b0888247b92d4604d7a13c5b0a1d20beff3278ee9196b462fdd662873fd432eed606515dbf09b00dd4ba6a030d9fa28f75" },
                { "fi", "5c4e1b6ac5747f6cab31ae2c2cd844b40780b3cfc4c30e9fd960502d59b1fa87464935a129898640c68c1c901f892c71c16a6afd60e635f541764d744f6b0e05" },
                { "fr", "37e51795c9beb8f639438edb4146c7bf57a03db575675de3a37ff9c1345248b06dda60630ecce015e77f58c9853b163dab61363d3c7191b3b4307916031aac77" },
                { "fur", "1fb927edd0d1e720022959f0166d24b0ebdfd5f5f09c477d21bcc9c52824907a4b3de9d61791c904ab24e7fac1aa14eb02020d217329f9eb570fa09337c7d2d2" },
                { "fy-NL", "cbb374ebefbffc5d267f4dfccc628555d5e4093b5c3d51a36cf8f046948a763b1b06c4ddb5e2148eeca9512edf653678825838446676cb44069090c788063a1f" },
                { "ga-IE", "d617e5ca96cfa17c30fd345aa85c5e6725bbbe8d58974430dbb9cb6070a7e984284f2a6bfcf9940e49388f9bb40ee43ba5a7e01705ce7ae38a66bc966133c328" },
                { "gd", "dc1f8d9dbce160655eace8d9d741cc9ac70890ea33d5c15112b1ca3b29f1d952067c80c1b76c38a6e8f36f046f2fed5466b7dcb491d9e8be9fa607dc64602fdd" },
                { "gl", "fcdf3528c84df950da0e3317f5a793d91b68c9cea6c7b45003f1674e12bfaadc4aa751f364da19f277994086c6a68785e7a00c2ad9d50a5a171bc2a72e1ded41" },
                { "gn", "2d9b53de49d1c9f0ed9e8fa56b3b027279a96ec10c087ff62c788de6021de6de8b43da55f2adf5bb19774bc3b5b2f765c547c5932822dbacd2794e744406fd8c" },
                { "gu-IN", "91b5e918652c1738efa236fdb245223bfaef8d511fdf145b5be9cd759cd50d29b69b13c3ffdd517c9b7e4d675b478017cc25dac907a66255dd3f4ed27bdf5c5f" },
                { "he", "06faee6955500f2ce70ba8c6dd929122fe90ae9717398a0b7e0392e6bab50177b235b188d6bfaed7c67bddd1741470b9817addfc8450f9f8f2537e5d9d2ee4fe" },
                { "hi-IN", "76442a78915ac16d53b55641335f7b723e407dbc036f4c27f88dff54845f7ab16fcca24e578219efb23138880ef7891a254a05f548f16ef58d678da5da0a73b5" },
                { "hr", "07d26c130f3fe6cb6c1a63af7c98c9c0007a4713c026dfa28ef067b29ea53f61fa6af5d3297794252d552b405fa786804b3e8d7c3a5843ef30c31d520858a992" },
                { "hsb", "c2fea507d8001cfb872731617e64f84272d55934665acafe5a1070bcf958d562d130fae775befc653ba2142d5d51e48f013cbc754c9ea4ef3b02ee4d5001b7b4" },
                { "hu", "b23f397d1ce48fb5d193889aa54af71d216c394ff234286b7e6372ae552896a2ab71d8fb9a768b3da256a31073315f15efb2dd76fce1ae516b6590af90506469" },
                { "hy-AM", "f14eff8f4549df1b36c6692ba571d05bb54a9bac315b18a5448a3b0465522f68bf84592b61d72ad45e2480974eab76a4aa45fe3d375f6407a0d008d973ed37bb" },
                { "ia", "03cfc1ae2ce89d32d2622e1d3ba8954fb4c782c5a2ce5478c70290db0fc56cb0ccb274d0b38756ca336faa1085d0e46b7128307d31783c8473a13692a9f8910b" },
                { "id", "12dc008d85c8927deb5d07e2c3e6affbd4f7227123253167ccd0216ae526ea66df57f86ffac717d267372953f09d58df4290a9750b18757935f712bd86676f32" },
                { "is", "824ff6e456bbafb881c29d28abc38e9370751441e9748a3bb38d4b97c18de62e228d007338f2aec3f555ec39b32d13e98ec11d7e3addf7b71649d696fb1395de" },
                { "it", "dc5c69a510c6443f7a914f0dc496b8a95a74a55cf96900f38744be228d556f67f44b0d287f230189cbcdbdce40e49f7a8776c8e26916bf18267f1e4b4cf66f8f" },
                { "ja", "efe5d6de996c6537eb4c3cde7ef1170107d60fca79ca7d8f5beccc61ff3c539fcba2f6a0d9bc7ceb3ccccc36ff13085e2a3c92feb1e15b57db428ca36aa01fde" },
                { "ka", "4e818865675ca713aa2a0dceafb21849d3a6063e9faa1774ade96eca521b355182b3b0bc895e33ae4ed728754a4696e7aff09c5f0a1085afd195ce4188df8cea" },
                { "kab", "8647d6fd019aedcd3a7e7f1c7bc168f09b7a5157db0e590ffb4d1825f55e312f8d55f0032405dfe43efc4619451663111e4f5901f2625bdc68e147e0642adf07" },
                { "kk", "89c12b7a330d45aff87cee205bf4280a31e89e9a87a898a5ca352baf600f4f910ef148c2f783f2695f7805dda7097cecb9aa00e4536e39758b62ab198f571537" },
                { "km", "71eb20c8ee747491b8dc41e0c4d0a06fe0d153e0edd83652bf720b29958cee30b67724014d82f34e0ead85dc227cdb80b8f3bf4d5d079f874b3bb456ea779f0c" },
                { "kn", "2e1a3b40e5b64370ad35babfcf3bd925f939b772ede1f36ba3246de8f76a12f0b0515591de917d23a9ebdc48fc72e10f92d6a493644bc3892d82d8dcc7d40eb7" },
                { "ko", "6b17c12ce790eed7ce2c187183752e35349a6fc02dc35c598e42498eefc04b2ed231b5d0a7383792cb997362237f8d67fd4afb8fb21c7fa000550ffa43abfc7b" },
                { "lij", "4b6c7a650e569b51a32394aa27fcba772d7a6c181f200f4248cc9e75828e85d3f78b61449a3cc7f5985494695c069dfc0f2fffca532e93ab782ca00da43aebab" },
                { "lt", "dbfec9ca1cf2d0bd6885feb0465e9651d22534f16e90c2d6497f97d3708689ded0917a2525ae710840e1a092b5d104813f6f2313da77d3823d4a96d33933c501" },
                { "lv", "49815fbd8da966b34a0cf99e88bcadda5a3ee414c657077715c61fe69cbecdb30d16847309d8e6fe3b4eb8e5df8dd8217f0a4f12b277ae67a5f576c140d3c619" },
                { "mk", "7b791e547397fbafa8b1b927b68d97026a259829b1896e438cbee983e2b5e23d3806a78dde13a300eda885126d8a9a10d21353506c4752ce3f94f992082e9117" },
                { "mr", "3b0b0b457e91bae21fe4c3c010f0939ccdea37414d0faff455265a279650fee2c0d33193df62002759ae1ebc9095a23498daaec75f1563cc118f3aeb50b0604c" },
                { "ms", "b0b428c85a24bbb3eaf4f879aa1c5a153498a129e5a6e001386de47678db236a05a9e71be1ee87ea6313ed7950b33529807d645775f7732aee36b8c7ab67637d" },
                { "my", "e3c5a5eb784814b823519637645ca1812731028ebcc51f7ebfc1864b6d8996614699e6f0f9259ccd70f9b36a94a7a5cd16a60df63aa4d1b0254872ca81e6acfa" },
                { "nb-NO", "1bb5ea1ed8b2b151d5d67a3661833a665303e034fad3a154d48c542ab656a57d71ae8e16db787a297cbd00e2f8d16cdc9b2f7786fb0d20b9ab1bcafce3f5a07a" },
                { "ne-NP", "9ca5257fc2a7f2dfe9f4ba633efcfc87826aab420667928415e6f4afa31ea58660fb06791d04e84648ce38c2a56eaea5f967110ca148f2571fb0d2bf32e17acf" },
                { "nl", "5935067a2ea64e7f0cb4363618d1787a89e836e3096ccce76b0d21733581da83f0ea2cecc5ae02403c9a1de463f1d3e6f5225c5ad1af20a089d76779bff56e67" },
                { "nn-NO", "4987ff15663a492e03005a80ea813adfbfe3fb4a3761db852998a338833d72aeea6ce8f8abded61fa7aab06e27de1c25aa0d3e76ef0904f939eb39ed575056f5" },
                { "oc", "36014f01966fdee9461ad6d634c77a036ff8d15075fd383a556bf4b61916d705eb5209a1c001c78abffb6addce5276138c69dded3e451ed52126b898d26090e5" },
                { "pa-IN", "b770c1ddfff6e39a294d9ed66a404f61483065c7f1134591173a1fd70a8b98ecb28d7f7051f2b3dd6068fdd06c0e13d41530d3799e7a54cb3aa3aa3992f60ab3" },
                { "pl", "d898c4653e8c253cf581f883cb771bc05b02f9a07d2da3b3f0b67a6566dbba10395cd7dcd798a502298d7a818967df34fa0af9e7882fe5192e9f57e70a020aa2" },
                { "pt-BR", "0c466714fa3e666f28bdf9f690210dacfb1d2a9ba73728a5fcb54b7ae3342d2631bd9f2f0bac140b084ef8442705ade1439708b7a9537405300641afc6b18304" },
                { "pt-PT", "d72fdd32b6bd5fcd9295ffddd26617d697ae303986aa61a51d0daaebaa162f8bf380487b760de26319f292c5654ad479ae6b50b869a81f794325241ea169c668" },
                { "rm", "207b6d64a94e6fb8f3a404563aaed2ba045d52a6aacab72670aa3589e357374c42bd608dbc51f855ad21eaebc6f32eaf484d22c84152a39bb60df546e8d9690b" },
                { "ro", "9186bc57cdbf6db5417e9535f1917eb33a507878244fc09b33c32ee45f9cb0a6200097c23445d25384845c7a980da40eb62520f58e3bc88b932b72bb006281fe" },
                { "ru", "e63bf88bf07df8e196c97c1c55521063bdd05bf795601524df64dc90092c5a468d81c94bbd481a6d248cd946b7c8aea20ca6c5f92473a96ec57c18760c10a421" },
                { "sat", "6db56935fe45453382ff07332fc08b9d8383ed8ab1d933a377bc57eb40fcedaca51e596a26f815af02301db9ddc00be13c44bf2bd1d6b3575f20ab4e18af2a57" },
                { "sc", "11dbb2bf60b27e6fd2696b6ebac90d64bff81d957c3746b7bbe91316879295eca9dd2394cae8ce0bd9a3d04de63351fa6e6586a9b0609922798c55411a7ab23e" },
                { "sco", "ea83f3087c27b678bc12c592bfe899ca43376fc3d6b61cb5dcc85c9e1f4e3931db22b02fb564ddd6b1567a02526a403b09f25f76deb3435b66c3d4187c41fe8f" },
                { "si", "bcd42a4220fbe5e692b33951ee6c96221ceba424681796014e991a83d193d607f9dfcc91e71ec084734f9069a062fc49f823f292b0b8fd13dceda8c7750523ce" },
                { "sk", "7efd30e34f9e9eb1e4b5d0ef1b9e49178ecee13b75c39354acc653a62b290e420ff355b67f932691cf5627b98fbb747aeddd1b5d9a4d584ae9eb3c3ef2151e4f" },
                { "sl", "263b2e8c9641f96e7b9722f9b3d2b4742dcef9bcbd61e71ef1386ad9e3fa4ce61f952f1cf0c6c0b5060b444ae515bd96546478a338aa84a520530bf746e1aec2" },
                { "son", "88230ae97fb09eba9d1576c84c5765367c990e08fd8ab053df7876ce156da13ae127d4b8161db626fb3f104d02cc2727b244f35ad24b52fb536edbf575481339" },
                { "sq", "ea0fc9ab254d82a052e66a5df9059d0ac4d719283e2db1934c02624ae63697e080ed272801d5cc6a3795ef9bea0a182c182440aeda3611e5db28cba52a40b456" },
                { "sr", "9823de1556761d8aa0a2e953ba909a0682f9f239f6a243f6df21c32575801025f3b9de054a801e5345c119c18e2f313737461731c183bce8b57d967262393a92" },
                { "sv-SE", "ca22410b64501ab4278dfedcd56e2ac1257f3c3aed151a12553dd95e5a80d361a28309e9e5d4f32bf5bfe3c2bb140ad600875888e09f6db260991a653cbf720c" },
                { "szl", "abe25f23dbebffa72804f632adfd9a0564d871b52e60a91eb6d29bf4ab8a60740084bfbb899e7e94f147014265fdc2a75c4d391ddebcc27567e18171a6b09184" },
                { "ta", "cf871634ab79e8e1decd0454101a099da566d7adaf2c72b9a4497c4e11805f578716e6e7ba420697a8a0fa3e4c2373b84de8874e25db71d81a7e6919e8195758" },
                { "te", "8cd433e8a4107b6a1f81cb492d6989b5924957027a218fee7bc37b74605615cf132ded398595835f6fcb2491875f81fcef6228a5c6e83befa2ffc4ab61528ad2" },
                { "tg", "8279c804ff7724c9d2ed657f137c1ebad82b8deb49bb8e282ae65efe9a04d21f3627c0c7b3d0ed861630a95122c4ad313c4c4fa51080d4599ad5758ba0ad4841" },
                { "th", "ab9fdb439c520335082875b03e164bae7a40b52c375b8466da08e6bc12639e1e3aa4fca2473fdebce7feb79460632c9e63f03615b0d8d3693686b2238ed3edf4" },
                { "tl", "4c6363ff16201dce98acb90b43f9ed1373d2fef0e2ee254c2fc41925a57d0b3b83f5299e0d6a300679afb77dd5aef00f8d63bfdb26dc259170213ae535d3f914" },
                { "tr", "968b939debe966adf632c179d6337ee5f829a63264a10cadee6c670ec6b99b06dae71fa55b241daaad0f4d27c8a1b77d2209879d1b46de3224267216e18df782" },
                { "trs", "c5035d02b9525daeb636c0802fb06fcf0b0ed3b2cee2686a06320269fa232a8d9887eb6fe6ebde306f0fdb3cae2521b3b1fc2a48c191b639029002d43ccba426" },
                { "uk", "5c59fb8be0bbc523ba571e98ba4e84f1d8586f3d6ea76fbf99db7a5374fed9fa47833c3f5fc95fd1714b2096653d6773110a6330ad054ba69f2ecb2344c071ca" },
                { "ur", "ab16394e0c25bc7b75b2cc606246fb41a92b38650259a1fd272d25836aef4f60d00ca0015a7c513ad0178911caf2d3c2ff06721c206d24c47bbac04dd451204f" },
                { "uz", "724d78d217db04997cb5d9c47755abffcd08810a71f7e61b5596669a083a4df2d71c5ff4eecc57690272bfece0c7cdfd9e62aca6c7cc6b26e7031f4825869355" },
                { "vi", "aef84b9aeef291fc28fef12b769a590c6183906bf5f112c3a26f9953fbe95771bcfe6eb002877dec9b900f08b1577924a65a47a48485277a0fd333867bdb60f7" },
                { "xh", "e91ae2bdda821cfda1d1b786b86dff8e04331baa49477532c7f60e13a44b0e7c5783b60568dee04cca6573cbcf20f1dd5f989d2f4fed982e44d24a7124db0c40" },
                { "zh-CN", "97daaeaa3fffc313e4ee0ee3317a124e55094348aa638f8a35ddd2297b129c93cb0129dbae54c1bfd9a8413ec1277424eb93ce02c19f7fb9388278452ec59912" },
                { "zh-TW", "06812196d4a7de8c9344a2ff9727a60b8319a49f3fab075ec36b27337437523645da4eec76bcc2f8ad1e5030627b0af197eebad5e9d8d6c769b22ec11682b842" }
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
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
                return versions[versions.Count - 1].full();
            }
            else
                return null;
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
                    // look for lines with language code and version for 32 bit
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
                    // look for line with the correct language code and version for 64 bit
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
