/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
using updater.versions;

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
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.8.0";


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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.8.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "c7e525815409d85e782e32bd63a20782141a99253be47a327021a6f49430c9e36f07b414291c50efa7e071b7a56aabf6c7db250e5a655003874bf8ab5ea9bf59" },
                { "ar", "20e43ad63ff2515bb9b0d5df0d2dc7b8eeaea01495a1c5ae8e7f88c63f2c65530336806f17ac172126186c942419cddb95fac7f70360f55c45fa77ab8cfbf0e5" },
                { "ast", "3b85f281ebdebfefabc10ded8ca0ba16e92fea8fc8406ec839ba872f8970f7928687ecb546c9c67c685ce89743cb0870ff25102fb48624d4cd0cb54acae8e6e9" },
                { "be", "f4f797338aa0cfd0787a7af17a55c689ebec74523258e7601ea8158d2b8ecf8a067585252b18d29f49135c46dd475ed454fa54403f07ce8a3cb9002f232e2367" },
                { "bg", "f532d51bc8ccc5ff83b0bd5d57dcd5be28cd480e0255fccdc2888d1f1ca578c9c6f9be2c78ae038a1d1832eaae5de2f35ba1ee940910fcb9d280cf1656d2b38e" },
                { "br", "97dfd50be5ae9c5572d69e5f249afa5434937865858cf17efa42be18b846287ceca5364f2b855969732aacb8cf2d72095423f559b36ab86b02fc86e674c3b7dc" },
                { "ca", "6c7e26aa134ade98d5f0ee6b76c58ca4731ad30146dd7b19daf3e6f952222489a63c71de05b3cdf4657cacf8d4f89f80569a829494b9fecc923ba41a3b1bb5d7" },
                { "cak", "4e2fd7393024c5a759a25f383e4f4495ab5c2a5b5d04a78bf991ea32fc3f0205d1bf03be51577c0178525862b4a1eca2df0f1b0a75bfb40c59c001e18690f14f" },
                { "cs", "7f40436994e1c76056501e2cada7904d405febfa96ce5ac43b39a5b96d8e487f34666472a3bd74fc49964c39c1d671acf4436a2b2397a5dde0fded8b891be7fd" },
                { "cy", "0cab5b7098217f15761e61680b772c9c75e98bb9761e88e2fa8494de2279b90f1ff145c07e25174c560c3918f4c2b98831eb8206b75f4bef3f4a1013755c1515" },
                { "da", "7dc7aed95eea055ef3ca0a6e1014e5a87f68bc1f0b331364f6b2589839990b242dd79f2223e246b9815b07977f8a9765b002b84d9a013386d46c914d47d8f6e9" },
                { "de", "0128af9b10383c2a6c718109b406da77814279395d3d0eb30171d691587e3c9e00e346f6c6a676ff329f3a5579f1b82cc7157b914f75dbf560d8df2201a0448e" },
                { "dsb", "52e0053b74c59dfef729b7913a6806432856bfa82da3490d7e44874d22def174bb99c54ad24e60bba65ae92a1d23b1cd6f64ad285a9703a39ea02f4667ccc7fe" },
                { "el", "f53b2e61832cfc7da9a63afa5dc37440b176b7a4193da81dca6a4c72033dcb20298385c1e6fd80dbd349f0ca8e00f36e11cc2a885c1a24e724ec09a8e33ad9b2" },
                { "en-CA", "ef84930a173b587ac947a05e58ecde0216ae5e94ec208037df0151ac3af244d0d75326d533730d4a91747370db44ea2c735dab3a2f294e38bd6df9026b1358d1" },
                { "en-GB", "f27555dc43ecf0b19078868ca8a7ab3424a90565a489f1b8cfe7be6eff8b6ada717efe260527127402ce7e7887ff1d1a920d4f12efeaf6dc8035de88703f2f85" },
                { "en-US", "cefa2752a2de2d304ab494a15cd76bb9bcb16715c5d3df80ca2eeddd97f76ad8da263485bce0e727ca22e8989d12f2ae7889d588f8db936c2bc8739309b87793" },
                { "es-AR", "4c58629bea123baef9566d766c6b33c78dcb1153eaad32f12c55cf920a9e281461d09f451e64bb73edc22b0eac8a0d94207fa441120827e5121cf03f6fa4225a" },
                { "es-ES", "b6ce2de58763008e330ba26138ae541848c0b3add0940f633e02df83272a22a1d9a578fa0315bd3fb798e8ef31bad1b748805c3f7f38e01a5c0d431913b5386a" },
                { "es-MX", "ad2b893d41f576c485c372be2fdc7f60477aa09ea0be60b62c2db33ded5c76770dbb76f1f2c9d6790b216987adc5f5c209989f188c0c7b8660046e085379fa58" },
                { "et", "8e99f70da6907c961c7a881dcb358eff5dd15ae362229687a9e0b3ac01de37379f55272de596fa0999d7740cb0ad3dad4903779fad027208736ef934f185d2c5" },
                { "eu", "62a23804f1897401aa87a2f7c4700b20deb02fd21aaeb1e5f31af330b75337defa31e01948811869927713372496b586c8c68f0fbb855e98de97ab13e92d9178" },
                { "fi", "90af6a73065fcfe252887cc8c9defb0cdfb21a759ae6cc264a4afdce917c77b77138b85c9b05ade173de5ce3de3be104dd5c527ab3f06a16c1c4bdebfb0b454e" },
                { "fr", "557fbd997b4e5a1bd7c064ad32d772566aec4e06fcd36f1fce4955b3e9c9f182729e003fc16d9c7c2efb22e88a692480504538fad0200605982b9a400d384d30" },
                { "fy-NL", "782b76a905c3fb956073409a62b6498d9058d46a5a291abfb9f6e2da70143ed695192048394b8ae59b21010f44419666df35953975e7501aad5653f58b3f1c46" },
                { "ga-IE", "1019e9e1bb99166841d031a94c867414894f1a2c0b651faef92c1b35dac360e5f989d22a11943cb1338d9265529459543d78b95108bc51b98d301bd4d003b7e0" },
                { "gd", "2f4836bc5cdf3c5dd15eff0830422f99d9db51632fc7a0c0ececc3daef7fb4e638543c6b79a0416eca51d2baa06db891d37a37d9383eef77c73f1f8d57e99f0c" },
                { "gl", "40b4ee3190b2b6310151e7f675d19ea6cd98ccf97b214af537fdf051c507c76a11819467931aa321377116bce378b9df73e589a600e9cc77c7cb7badc628e312" },
                { "he", "06ec3124e928c5db334338615343bb287c05ae616c31bc8179a05635a080a39d8a20967d383c1da4b1dabe5501f2e5d60e09f82b00c44d687d90e2e65e58c0c5" },
                { "hr", "3f02472cb92d79ab30b111187a151554432dcbfd0234bb91873cc4f722b5bd2d334f877b412c9413f6070764b4895860d8ff0b3257095ebb5efe72eb539d3219" },
                { "hsb", "f5a6d92ed66f89d560c74a453f7e0d5f084c680a83bb6302cabb0a250ad01d304489c69f5318380937bc06602dcc554e1f6bc227bdea944139949382f85bf0ca" },
                { "hu", "855e4dc91b99fc09e08575dca7b0290e6547e3964c97a1ce938a7f82a35883da00c4fa4a3dbea6a33605d2068a836f90a42c154f82974e4c5759b1f8b04cbf63" },
                { "hy-AM", "dd6f713fe316e4b153ac1286ae3586e29285369dbd867c4e1a9d277855d2dd9149a1f12d4d0eede5ba86afc33d58c851b73819762ac89720b5ee0bf8279abfce" },
                { "id", "bd792ffb2cd9a92ae733c9fb898e654f0b75f53578cc90f7f58f915f2d0f8f6a84a77c78b78724660e2a2466d2ca23304001067f582f3d777979a45af62bc0c5" },
                { "is", "c5d324b56e831c2542d8ecaf16c3ed2c55497b5fbcd8bfc9cbe49231fbff961fb443ba5bdac1dbbd8b8bd2196f6ad033f7cad820544238c2bfcfe50584e504d6" },
                { "it", "db9778a5274caac37fcb2bf76168681fd6e008b6dd049366bb7b0bff8d162e5c9414758fa2b923e4f38dcb5179dc34e312a2d07011111f8cab05aa00fcda4855" },
                { "ja", "3e9919ea84ea20a1b5c1a0d5946b821e274e11a2598e06328bd86901e3e0d827bb6ad7a2b78dfe18e969a67d68f8c8c1f4c2332fd64fe8e80cbef3919f1726a6" },
                { "ka", "44d89ca5dcf93fd98f27c1c5b555563756289c1a1fa925e202bd91b5d5f3ca93a77da2dfa2e4f4a5a0544fe9e925167f9529b668b960bdb0617903fe6588167c" },
                { "kab", "8c87707764d704969f636a7c11bcdea6d5cf1ecb2929dddbfa654a7f6c3dcdce0086906d74174de278602bd1ee65d1b32cbfb2b00db9366fef4277b2cc033cd1" },
                { "kk", "c0eb93809ea88ed313a7f09c9a7acba4446c983194198e9e69ebe6adb7803540e596c127f54fb0df3068269fb1b97d0f6cbc5f5ebbf06ff8274ae830555ef4b1" },
                { "ko", "ab538aefe6062d939ea3744789809818dc4f84e8dd4a6a4ebf5cce5ede62afaf7095fdc97d579549dee6e2fd6963a6b831bfffb9f86d2078f5f39fb7e9a218ce" },
                { "lt", "6015da9c8e08dbdaebf0661ca19c245cf00f077e62c779bbb79d5de6e4f54d2fe376bbc96bf7236b775f4ee4057208e76dd58c920ea881aff740aa2b96546a5d" },
                { "lv", "92aeb0a4ca16d3589c151ace9e955819f80de9844cf59b806a800b3985244ab0ccc6d452cff585befb4233c9014972fb014ff1a341b6b0641c2db159d81ee7c0" },
                { "ms", "e9822c6f393c1fa4d25caaec8e7f83bac9501df117407a4c0f1784bd83e1e212b570f97532715346bf7977940a6446533f34cbe524674a3a21f5cc44bfb79462" },
                { "nb-NO", "1275f23b036e7c8889badf82fdd9929088f4a886394e2d67306e68def4ba606c139cb3f432af899a7117023a85361fa2f822cecc93975d055a6c5417e0900b6c" },
                { "nl", "0270abb3119103c9d4ad37694df0426e8232195259709af0a698b82d9844cdf197246d83d5cad6cb29fa95123d25853ebdd6c4b8189d4fc0009b8408a74c522a" },
                { "nn-NO", "54885397471b7969a68d2ce4adb087eeb582f6c8d85f12c9fa741dbfe5c6c82c1943feb8287886880437cd7e64fff3b42d70a8e14d75dae671a47245cf9b291c" },
                { "pa-IN", "50f99208d3d1a6a550211a2f70968b8db2f02a8fdb38130033d6d7def54e62866701a1f903ab4c254ccc9455d0c8c207c089efdf156c8d4f889f782d6b90a5ac" },
                { "pl", "b5a9b1aba3823be63cf823acecfd5406a3d3b0e50316250d085dc2915ff547acefc7367f67415a2cb956156dd911a98a67a27b533ccf9765fbd711a0d5555013" },
                { "pt-BR", "378686e2e0c1fd71b546c09069154cdc2a00bbefc90c29ff893a4ef32e688741f72346d875807e4058aa72cc21835e00d577f95e77eb7bd01100300dd15d6fce" },
                { "pt-PT", "8e8522a66f0902773891c3674f93ffe8a86067e0b6b589949bbc78359ccf2527a3f733c1d14acff959111a1ca0ec44657affbed5aa57b592221ec614c727b2e6" },
                { "rm", "a30d3291351909550481a4657abccd2469c773315c7509003cc04ba08b017e73383b4e90091b45f2eb8ee2af6ac6ce5b4dae19cfa581200621d1566e741b8bec" },
                { "ro", "3d4919a97d43e7895240c34de25372bc75443d3a0a673acde9212cbfc8bdf685b7a275af6fa13d64cd3ca1e0c91de22d0cf54d471e0180080a8ad68f39e23e2a" },
                { "ru", "05d0836d280032f84e8049726db22f4b9d207094632591d5596441dda8ce823661f9095bfd3f2f63271f13b55d921db07a6e02fc3a3357262fe35bbc15318794" },
                { "sk", "2abe1cf5a14cba027833e458157ebab03f485218b59cbd3e59a3dc9a0f87b3c78718dbd9e807e1ecb905463955b055d83ee71f34ed1fe2b56ece89f3777701ce" },
                { "sl", "f8ac7cf8918cc56f2b164e6beb93351a2df4619c0716b2a880c0437f3b488ffbfe60bf095072785569ee65ba09eef7e1f7642f4835f5531857a743fe9c1aea64" },
                { "sq", "88fb518aeaa8547bfa428d63b219f420542991e65f2fade001943e8295c42c0919c17c76abe04483bd9ada5d6a69472c659658de623b6c07f3cb21e9568fcf45" },
                { "sr", "25cd26acdae51d32099e5cfdea9f5e12112562711e727ac45e1ac307174e894b5d110b021742f3de35b2723f48a6ee20f0682d701fd590e3fb740399c589daf8" },
                { "sv-SE", "2a2361c85ac2f5545f05de52a6d6a1b7536a94d88e6797dcb4e8c6e512371f9fc0b82f0f6e62cf9ff07129195298f34930c7b34c2f7e18ce59571c79b668aaad" },
                { "th", "7dbe502ad7ca19ee1ec90af14b1f6c16a43eacd6deb673a818a2310760541022165839996f51bf8ea4112d2f763b20c5283c44f59afd1042f094b27bda9582db" },
                { "tr", "23d51f004c704b45941eb0f89c4712db9d101e0d42a08f4c360edbc07c151b5da8ec0f5a47eab1512dec893fe75a4904f12ab4f3763481e5bc7c2895dfbec4de" },
                { "uk", "792a6287c0e5498d92990b038d12328ad939eb9d751fae90dd73e90e61d798388f12939d344bc5eb0a657f5f8aa90c4f505a073f68379940e78d552ca84f4ec1" },
                { "uz", "95ea87b92590ec121088d700440795485e4efafb1e6af9ed5e209862b7546e41d60b711f06d662ee86a7264106cd8d880da74be40483d9f5609099ddc643bf0c" },
                { "vi", "0c0ad0ab369697e59b8016bbc06ff7799aae247d7973ef57d1a2c096009579b865aeaabf5e154a9571ba44fe0878de57277bbaadfd30fa7c85a59d27d135dfb6" },
                { "zh-CN", "5332d4bfef08f47a8ead237bcc2d432c73ba844d467c62983a3141682fde62d5f7cec531cd8c97f4b9e6b1828eda8cb34434e2cf64febec89b81ed79fb3f64ce" },
                { "zh-TW", "e3edccfe0f5b826cb52275f49da5329df6e91ceff9699e77ab0ea3b42a1639dc9adeebda9485fa3c8ee9d1263109b23aab5097d0ba4ee1c006dc0b8f9c54ef24" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.8.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "500931dfa2bce21d4dea6d75b38e7246e0aa041416a2b297576796f2710d22b747cd74a09fb094a7236543e2bf596f56ed1dc6fffeea9611e1dcc84f6959f409" },
                { "ar", "67f6bbb27b93636f46570a57de9673de03e867a35a2ac0ddc091c14b437351fb424fc26a3b73dccbf2790502786afd01805eaa7b279a67b8033de606732b1927" },
                { "ast", "5cbe9c036f56f562b53cc1c99dfafda517bb9d6fd308c6a557668851322a3e1b8939b37bf5c71982a1f191c8881d83968f9a197ac47958fe2f69cedf76a58c49" },
                { "be", "f9a1c414000b08e3f34b980f7f706f61d5e01b9634f7072698171102447a623177017da39f88aef53fd38f5f906ca9b441a3d9c9954fa231ffebdb56829d7d71" },
                { "bg", "5c5c53448613b2ddc22c0df36dc134526d6242f54283bfe8c6b0ede249a8ba4702df57b84709516a576a94b3fbdf525b7fe6685403f30f393c7f67a4e3eaa19a" },
                { "br", "d17340ff99f4693f95e88e89a53eca95daabe1419c22a15873af88b879e52545b232de3daecad5af998c664941590f93c897b956e9e487dd3c8f0d5f170cadb5" },
                { "ca", "36e9210610c35ae0d1f2c639ed866eb5c50f49dd7a374bc7ed60552f8273d96fb54510f2ac976346d6333cafb2bba0ce647861377a2f3e23602f9dd8b632531f" },
                { "cak", "57a987cb78a28ed10e3f0948e792335030c80778c3f9199b86dd32ed9cec408f827fef2058a2d59f31ba0d04fdfbe4830be34f07bed953294ade8dc2142167da" },
                { "cs", "5c3fabc17453f172305dfdefa7bc2d224ea433a5442d8863a6daa7a20d3d79b360d6a16a5ddb10f511c2b51a1a67dc18b20f555959fc201b59b6b3e22149f77f" },
                { "cy", "6ee0358b83464213ae77072a87b2fc158d05aaa89e8f84f41921a81a08ba2b02391c94864b413f504f25736c7d2926f110820b22c9ac9441fdbe802626301690" },
                { "da", "e9c9e55631d0ef392a71af97e17bef9ce57b8559eb47f016cb861b35f67b9c1d63baccb1ce19bc72d14cc90106fafffc8213b4c1ad8801f4327bf02ad879a43d" },
                { "de", "a8983931796dd65f27f3b70c1b7c4552c9e08f9f5bee5b84881688c2162a28183dcfb9e66d502c242995fc4c819b3b277194bf6e5e3ecac623476761465c86a4" },
                { "dsb", "690e7f1f08ca687ec4a28ec685ee0b9c23d22caf4352507e7afbe7229e17a7af5d8469152b50c69d6382fb5a4b4022951c9f39870cf147c269c523d1e78b5526" },
                { "el", "eb8804fd82f29a7406eeb44f8706d2c15dfd92eb1b19c0c25ee2b3772125bee4271c8aa92f38af9ba0357f53e9fdffc3f8d2bb756a098095108448ef36f14568" },
                { "en-CA", "67b508c38f61a510bc025cd7dc3320e5a3987f718678663f340abef0871b6cf888b4a02e9986052de6c193e65c9c2f55512fd61a6dbf466997f55e6631c0956a" },
                { "en-GB", "53dc824ad9d3e4a7d153d0633ccfcb76a9f7261c6359d712b1973b37c88b1d0021d4163cb6711d01b887b4f7546664186270f689cc83a5604894bbf5e3789dfb" },
                { "en-US", "703605843071429a657c9cbbdec38ea358bc5a578170e4e519fd1582ae1fdc99d611fb49816378c4d0591be9626bd8db4e9e1ccac1b228c1c13e06dec81542b8" },
                { "es-AR", "5dd7fd3ac334bc39e59d5c6c7c6c64c8a3a3e586c38650e898ac4d7db88d84e692e2efb02d4f128bee7f128ff69f2fc44f491abfe2edc2f8cfb21cc24812ac65" },
                { "es-ES", "c90ecf809491398e71746430eb56118a776bb8f721067ba2119b08715ff0f98254ead8edc4c0565bc2c72375efbea067c46296a29b031f09c810c9d5d02adfb9" },
                { "es-MX", "7b7ba709b85e25f70c24139999b2fd8f44f2d4fbf070424e53c44f3a82e4816ffcbde9da813f37ddd771c60c9a5b251438161b5b93448349585c05806b418101" },
                { "et", "4fc5b6ddbccebc04e8cf1a5f83f253f16c22c107ee9238cb1402d7c8d856d80f52c66e70ff28265adaa1b4f9db36c1d8a8cc298cc0d06f4cb69f45dbded2112f" },
                { "eu", "18f926c505f6764284b8c19838a945089539ae11a0a68e2146913fa721d6f8853e7eb0787f5f773a22459ff67e38d1515e9f7806984b2cb425c5c1d5414c71a3" },
                { "fi", "3373bb2fe8c44fb7d1b313acd74dd99a91becc92e0d7c24c0a1e4b1f0fdc8c0f1880864281ea90a2fe98ea510d1276091318b53bfac1a62c6220de557b74c7d1" },
                { "fr", "5fb7d531425aa22f6aeee58047db11c6ed613896d11a7ffdf87a839d2fb8ef8a126b499575f9907c5988999932abc13a0a78c8630a66cb99d076c14bbde101a6" },
                { "fy-NL", "eacf6553496858b58c6ae400dbe6c9232bd7d92ede5c7261028e63d0ee307325bdc05a03ab83dcaab43db957311d31b3123236b35c02b94688acc3131834be53" },
                { "ga-IE", "43508935ef773bd4ddc10c7c98bdc7b4b2b42f1c9f8222e5e5d1505b5e93280a80ecf42193a36c7cee994bb4c471bc166215c9bc8e7f1bc1ad583fe71a31b505" },
                { "gd", "e12de10d9e86364788f791d70d89532c06f9739fe7ff6f7aeb1f52b3725df82e11fe57fc024281b6aed989a06ac0473e54801ea17ab10cba09534856edaca14c" },
                { "gl", "2abd009503027e4841acfbdba39b58603739248fdb1dfa41c0d203c4617621e7d29c8ecbbd5bad68cd3f953e00c0389d0198fe8d7cdea547a6ad007d62afeddd" },
                { "he", "298226def014d36a0f9da50ccfa39feb44683f2497479c7a8b8eb8887163abbab682d9dadced5a78f971e3a9b73fb9661a30e6a4e585e228c456796016d5125b" },
                { "hr", "e40013c6184c43233b421a410d8d918cbc9c9d60e0d1e7170cb7733a3b664045dc84f0056d87d94b688f36a9c5c1728e1d3edad4ef537a9de613867c9df03f62" },
                { "hsb", "4bdfd767c984732563be1934b8cf63cd0d4d81c4b55648d70aedf3050906198902ea06a3cd402b0329040e090c64028552bc3e9a78c033ffc3db5358f0368462" },
                { "hu", "39a64e60b473fcf03103dba6a56eb64814f9fd79f0581d11001e4aa6cdcffe4810f76bd7c6a8476c8128d524c929db23963e2da8cc847be2cd14c88872a3883d" },
                { "hy-AM", "0f7e2a55e4837274fa02b26b8499deed4ff38a35ee0cea36f9d57326dc2edb7f0d68102895ae313eb35da880d036f0c2a0acb95e4416db10fa41c0dcd98ac564" },
                { "id", "29b8ce61ee3a2c45111e0d04bac03e34d7e75004cf21c5b9a9e2ab7f248262bcbf70e355ac5b9233c3877f1ededfb8e10da9d5c09d5b92dc464866ba8e2daa8b" },
                { "is", "9e578646418080a6851f99561065fe936d603c27eab407b75f1694d19810f529e57ff5e9fb02663c20b16cce45eaefe11e06bb7df6910c9fbd6ba0865dd5fa1c" },
                { "it", "a7f0a3cce91b08fdb57b641b256fe6a7a824228e24962023962ebf95355b4bf95f7cf6a341b9f2d8aa3468b7d21a87f9961de2f75901d19bfee3130cc1e9ba6d" },
                { "ja", "465b99a52a595b97a364e5fb22022495dff80c3e14e2d3045a0b985fd0a4426abbbc8d6655fcd02c676ff1d1e555ce99c8b2683ed96bc0e715d989c5e34c7f4b" },
                { "ka", "e8c972b3422f2f2e0006e2c807dcd4a77a5bdcde14faf0ac8b7536e985e1c3dfb0b55f951a83a5a915a9eac5dcfbd05158ac18d2a1dbef622a7edc59ee609172" },
                { "kab", "ef7fb139fb1311611fc9e4bc557a6b00a0b43cd6b4ae12b4b900253e547a44bb0894a26c838728f91abd3e99d823a405605f02122bdcdb52104e8982d78c9f28" },
                { "kk", "756d138042834cae182298829fb7de116237ca362da5d767906178f69d467dd8b9d047e0be1758d4ca329af2fd77f58655e30d5ee1a1675084616af3443418d8" },
                { "ko", "47dced64ade15421056b4e239226c5ba821328556b49504fe547f771752126dd3e2df805ae90ded39e6c7e9e5f592c0e43ce6b485f69bca460092ac80c6cd228" },
                { "lt", "6bbc3045f50015404ce716127acd5c279fb90184950f4d62417d7bccab87f360386d733ae7acb6ff48107bf4d733b87b27f96d323d081ce417d95f662a451c2e" },
                { "lv", "2b9b64d85e378e69d93b34bae5cdae5126cbc3cc029f3afd95bbcf16ff7dfd19f09b91bddbc03130747758d2983c9e21d77078cfcc8c0aa8f1c7e0c123820941" },
                { "ms", "80935ac271a1d5fc6a59f3cf513b9dd64e1918836c0a8e92a0aa46f1a0c258ca8fc73cacc0812233d332247cc06d2f1b2462d5958a4aafd32d9e45276c07b589" },
                { "nb-NO", "a4543021560f99e9aac784b7e930fd22e06496c40c9a0a66757180190ea621a316538f9d61f7bf73ba7877ed0018156e1ec469a1e606c6043612fcbaf2aa67ab" },
                { "nl", "6dd320bcd2b2634d07ff0caa3399cd686763cb9bff8b14bdfe02bb02a454a2b2e5f07f77a159b63ca1566f9d594dffb73db0a35a45b2d53bd0559c2d118f3f18" },
                { "nn-NO", "4f4ce6702f6d346eb151901a1df1c650b93b080fcbcbffc7a7da02841ba2f0aa5c75cc8e15ff1b25e1e94959ec533e837cf941bce56bd71f2929be8d5e7017ea" },
                { "pa-IN", "7be740d2e725d1974886168461fb42a527725998aa54da1180101973c91fc61de91889cf34143b6b0e8497b69904475d0b0be0df81602d1208fbe7f5e79176b4" },
                { "pl", "23c93a4e6859d7ec6f2f740eb95ca5f468f5a934239cc517452942ab31e1776da3bf0b10f9de4cd87236ed30bb3a6317ad2ea23d3a4adbece0e6dd56b255e9e7" },
                { "pt-BR", "da19d1ffb21efeebc61e46150758d9bd918255858ac9c6fe9e7570d84cf54ee239b0ca60bced3686de4592bd4f291607ad06b53e223bdfe51b9a3e8678cf35b1" },
                { "pt-PT", "08bcb94cdbf42bad89bbf13f077964b04ee7905d8584c069786459468afa93f13be5be501969069b0637556f7b742bf75c253eac15155cb2e90a98b6a9a2a936" },
                { "rm", "fd17dd5bd839447a7f75c37424bdaad82ac7d5a4b11f8d12776aaa45edba26b23c09383587d33929bdf1a9008e7c2ee56c29490eaf2d520f2d669e949aa30ba6" },
                { "ro", "85a3ff8536df23b33c294cd5873f768d8d736770d2bb87959333ccbd3d81a607d27a367a70179b5e03dc70dbd9777ef5935760bad83f77a37846dcf6ba564d81" },
                { "ru", "3160ff663399299a22dd7a1b386e7c71d89b58ced711009194f5b0d02c8d2e19a8f2c321d206f1518a186c6571d4c43621ba1052070edbe1c514ef058516cb2d" },
                { "sk", "e62c51379107111b384c4809e1fba815e7c3bc8aba9a4796f4370f3314e381c0c346b329076ba899e57fd78a0fba8b3c5ed6bbcbc7682bdf0113851937ee520f" },
                { "sl", "158a18b00c37a996c89b3a1aafc80c0aea4bb171248630527e52f31559f5e63641589a46c9fca95130f4ebd5e8a54091a6f83a4ab68b5f3c4417d54d2fea2b39" },
                { "sq", "600934b6c4883f4c69e05823521d5eeb2d12ec70ad64f62c7d89cf701c0988d2ba1f7353a05a4253f41494d36f9ad029d45218800557411345bdf27e2626b607" },
                { "sr", "878bf9238ed59c26ace8524c42bd43b6a7ea6a889262e734511639b812997b4c6769edb527f04bb9572bfbf812ef408475b897c972b9c6d129018beb686a08e7" },
                { "sv-SE", "cf9c593d93093d1cefa729e5d06ff6ae3ba2aa4624412b1471a8b04aa548d605818acb78bfcf1d80b1fa5c4d3f0e62307f985abb3859e65711b77f641569c581" },
                { "th", "38c1f6d6926a8b23c160b172a7e7c948547f4286f7560bf17b8c4eec7e8e055d6b35bdd52b30278717ec9fc928e6e941ca34de26e9d504e8826b165d3a2dfdfa" },
                { "tr", "896138fa7f12ecf5629c9daf9aca8e2e02e1004be2dbc969ea49c59549fc9983a6ce0ed4076a703fd4c31528487cccfe2d5654a9b866e7fe6a981c1d739eea52" },
                { "uk", "fd23600275b4ca6191c017a3baa60e460272fa919f834c7714e7c2073957b9a83b17bcb25ac773971ddd25e20712fc0eb2ea76f4aeca959c38952b4269571315" },
                { "uz", "56ad39eb582a3588c086711db61e687cb6c34606d187bef6669f722116f2adfee28b69c02c302ba73a01fd3994ac7e2b48ed92027fcaabb4020f4d699fb5f533" },
                { "vi", "a37f434235d01bf5bce50c3eae512b80037c5564b95e44575e1eb28a131a6876a4b28fb84e3e4816deae16916158f1f0dc1535d69678d1592c3f83653e09daf4" },
                { "zh-CN", "d8f4e97417a20b9d39801cfcc125981beed386606adfd1a97f747ec584aea3e21cb57dd5a4b1dd9b03bb768d6c90b4051ab8f61f1bb615f5afd7fed09a2667db" },
                { "zh-TW", "e1fd1174eae20a84e2d01bc3c36e3e3134c6418805f4280d07dff3599120d1a833cb2a4e095bf7b9a16c44d39d35f23a170bb7dfbb31e76b1bcd775106bcf6c3" }
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
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                knownVersion,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win32/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win64/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
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
            return ["thunderbird-" + languageCode.ToLower(), "thunderbird"];
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-esr-latest&os=win&lang=" + languageCode;
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
                Triple current = new(currentVersion);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }

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
             * https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
             * Common lines look like
             * "3881bf28...e2ab  win32/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 32-bit installer, and like
             * "20fd118b...f4a2  win64/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "esr/SHA512SUMS";
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
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return [
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            ];
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
            return ["thunderbird"];
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
