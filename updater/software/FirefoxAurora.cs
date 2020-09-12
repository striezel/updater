/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020  Dirk Stolle

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
using System.Net;
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
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "81.0b1";

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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains<string>(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            //Do not set checksum explicitly, because aurora releases change too often.
            // Instead we try to get them on demand, when needed.
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
            // https://ftp.mozilla.org/pub/devedition/releases/81.0b1/SHA512SUMS
            var result = new Dictionary<string, string>();

            result.Add("ach", "c937ab55253b64afdf7f73af88b736cc5f4579ab9799584cbfe4e5b1f2f675e278437d1efed7159f993a2a4c624893eb795097a5f92e8b8cdf7942ac7cad6131");
            result.Add("af", "5e4c7b7001732f8ca96252876d48c0858d3757cd5ceb307c31e7ce446141c0c2407814d9eb9227dfb1f0db67cd183a27925ef6d6cf776ea25c8d8683f9bfeb2a");
            result.Add("an", "d7bbba49fbc59717c6f1ce200ca4e3ff6b25c1664a95b622835969aa5d15838b67ae6c80b8e19b9fd158304eba2190f651dbdeee6903e43df6f09f6ce57e9ddb");
            result.Add("ar", "e591c31d640135c638697590a78792d43495e8060493aebe5b862d76814cdeda4ccc312a22108b91bf6042714805c5d54728d507e4eec22ee6fda159c4f2a6c4");
            result.Add("ast", "e429df5420895e325828e993fc806d91da7c7adf933a77706b3208bd0e0e89c6224c135017e8a4d738e925f9a90cdd6a97d8de237eb23ca39c719a8e850dd24e");
            result.Add("az", "0815e2893568d4a1d351db9673d9562697cb66a8a068a029b46633a04c88d13e15830ecdc0fc6080cc34dceb47997c385054ee427c467b2b3aaa88b1647204f2");
            result.Add("be", "4cbdc048090302799e279f2d57dfabf7d91892270377ddf940b44cb8ea90bcfb3323ba25a03abbfd567fa65ec9fea29eb409e5655f4a469e62c87830120a3fe8");
            result.Add("bg", "5d8fb9f0fabdeaf19d9a060d0920289bc979e7bf4a2a169438c73bf364c74b5ac2f7716e5f88fe332e3e87ca2bbea08b1a4558db70eb36f92f5acd61d775b5a3");
            result.Add("bn", "043536f9ef4e8a221b03ab307502cb1d1f72d60179b6f6ded37975db877702cbf0151762f246fe2794c17b899a0c4149b85c9e840216e0f96f753e5246283649");
            result.Add("br", "deb1a06517e43152f9e605a23134d1e525cb275e232a3f0e0fc85693260f1a8616eccfdf036f470e4f8233460066c3b795761f44f89d3e6c59fa5f3eaa6aca95");
            result.Add("bs", "97442b0ef25e8fc025a680f32feb7ffa16b0c4003bd453c845cf36650a6ed3ffb0b3e3b771b32e267ec0dbaed719832207338c488417691ed1c2dcdddfd2cac2");
            result.Add("ca", "a94ae58d32a7ac0c2e838aba24160751cdee649bb6063206cb6844e893db8829e23526f17ca3e20b0c97569df465460ea0f5423340a0cee9eb79952ff6e55e77");
            result.Add("cak", "893c639fb6df0ccb291391d1765acc4fcaa00081267dfe4e1c7571d8844847099d48c0ec741cf4b48a237b0c0a8864aaa123ee5fa913325bc6b1ebd8af2d7475");
            result.Add("cs", "599d5ca737d655a8f5f96bb5efc598da114a6ed7be0e11c264ba2ca5691b77157c0063026b1056dcfad3684d0c837b395d81e6e1cc9168dacc243efb3d923575");
            result.Add("cy", "3cbc653e85945da3f84fa4c20bcfed8ba0ec4ccc1e06035bf6f74db7c4d10fdb54966702e40b0a85a147ccddaf8ea571eba916de3fc14438184672a928090d16");
            result.Add("da", "f64ea793eb494b8df5c2cbb85213216cfcde097c15b9218f0329e36e48c60b3a8949a2ad0a543af3aedfb615a7b4a9d7055b230566d4095def6f9af940daf4b0");
            result.Add("de", "d89003bb4d8b700a9ac2dcc24fa5706e02b965fa25ec486e68544d08e41e0aef67a94bab2b3135ac1df70a8cb84a468ef8a8d0ae0fa8ae20b825560ce6dcd14f");
            result.Add("dsb", "539df346fbaa71eb3cc6b86036996ecb723efad80e39f0a29ac0b336bdda96e39f73891a033e12f6ef0fc480720936c5402582ead380532cdb30704c932c6f6f");
            result.Add("el", "52bc91270795a8f3e87e8ba8ac0658531f99c140f2bfc73ef6c9697a7c4c508d12ba456eea7b346eefd54ace5c626bcbb396d9c6f81e1a3d12f8f0ec7352cf6c");
            result.Add("en-CA", "1712c058ad84b186567c4a510b7a5b647186645307367da336b4af5f6801ff6664fc946c38d32e271852b89072861fa23b5bb4f482ec767262d0ce2e9bf9e016");
            result.Add("en-GB", "ec0955edc638a3c2cdb3ff94578d32c7ec9c821e7df499d03eb412341d02ec5e264564f91acb427eb45cb62fcfc61cf1a87e6b66f2a3cd4c77db05941d2fc93c");
            result.Add("en-US", "762b79348b7b39840679337c499a35243c318adbd977ad793e85d2670717f83d253bbae8e369b10038e64652ba7f14026bab138db36e37e109bdbed4d2d8e608");
            result.Add("eo", "0c6d88daf31a0a4650604443d6f9fa2bc782d0fb15c3ddc5c139319b63b99bed141a9ce68f66d945fc0d327b9421fd074a9ac94659168d6dd9e404c10fb21c0d");
            result.Add("es-AR", "21fddf67cc7170e3b708123ee7c7ce7569e35ff4416fbf0b58a0fd454acbc09c026ab7f5f82ca3bd801058210f4d9b5734e4ebc5d1a8b502ed5fb3799f950a31");
            result.Add("es-CL", "00f637829456f45f07cf204582ea5b1e9beaa57c0903e70c7d37a5082afde78018ce38cb365fa42a8e2fb633a0537d7c31d0dca17d2426ada9299f855cedc917");
            result.Add("es-ES", "eb8cf74798d9a2de35d3c20290eeecb73e848eefa3783467e3ecbbbb38a5b52e215b316662efb53eef2869695e6ce1f9bb99988a6c2960762bf56ab1f1c855eb");
            result.Add("es-MX", "6186eada8ce579954feb35bc2798843e388dc6a913016d907d10cda97ff4ddfa472c0e071ddd65bf3b5e96bab2f123d8fe4fe6140c8e201b3788a43ff99593da");
            result.Add("et", "93872c18b17731a2cdd1ef404506462e53c6eb4b7efaa65d231288f44a548147fb4ada66d96b43e2c1378e21aad9eed93f1e6ccdf4a736b3ddd2b98f0acb3a13");
            result.Add("eu", "40400b545adeab1365c0352afa84df5c795bc88b7d7f144fc3437d60814928ebed9a142034374852286c9c69526597c43107ec309e12176c185af886a294f168");
            result.Add("fa", "5e2ab60e8bde7c925e4b03983f38073316ed73b762e57a7f49f230da23a979ba398e363805a7db4235147f4648641c0addfa9aef6b8eceb3f1d8c542793e1195");
            result.Add("ff", "ff9bb01d80ada66039366d5e13c3e3e0860418b46789d7b40576f98971469763b40826277bb19859b0702649c572009011fc1d22a3c3814f30732c2134207c71");
            result.Add("fi", "f0279de1f1068764078e99179f1a6c926db88ae2a3b6af9875da17b05057ad5801f897e10c907cd69a6a34117d6f0082de98fb4e289c0e3f45365ef9508647a6");
            result.Add("fr", "85c718dd4d2105590b314ff4740e9fbb970d1b1b30effb4dc1ab40920221880b516c06183bd2a6704bb8519a67ae347177300a39fab9099d901baf7f42e53071");
            result.Add("fy-NL", "b768d435b8c828d9e110d916d896cf5ef8b41ce805aee84a22c706afce7daf10767c0e86b4dff9159c03158ae2a9b7b55b91b7fb803160c4bf44239f08ffd249");
            result.Add("ga-IE", "1e5eb8a771e9fc7e78e1357e65c693dee13d2f8014713340bc3f539c8cb81754cac83833cdf4635e4b8a4121fe7371fabfeef3061da9a84182b9ce589b7e1b7d");
            result.Add("gd", "1427caf3b399611be465dfba6c5461620c23d58cc0412ef7cf014cdb84b220443741ff54e6a516a6fbb8473dd14318e1ce9ac802992ebd30544a6b8c4d1134b0");
            result.Add("gl", "c26763ef98cd542f6a9c6c1abf6ca755de8041a20c88f3bdcb74a547d274575e995b7e7ffcf74a3e8a1eb58c1f1b0c456b084f49dac849c44d639d4b02aa5de2");
            result.Add("gn", "3f4e3bef6c6a5766daf4aaac39cefc9cbde309f6de6efc0cb24e2bf5597b595d4ea1320b8dc3468d294a89dea1348325401f3588a31ad6ad16ee6130a94e5eb3");
            result.Add("gu-IN", "1ac8c1668e0c6a53344e20c5c1f030cf41279461100fc680949149fe103963571ee69a80fa657e88568c497bab8d9e9907a5c2ab95b49abf069f643d10491d85");
            result.Add("he", "74254f2c6ab745fb17f29d93a7971d1d88370ba66eeaab886eb80be5d550f72071bcfb7ef309e3303d8595c6743b90888f3f581f7ec4b9dfd3de29b85ee75883");
            result.Add("hi-IN", "50fd075c9687fbd12242655573a3d143e6a2ddfb8abefa6e4f735e7128437d6b6d5fcbe3090a1f8a3882d51ebb1c6c0dd606c285b292f29ec48425cfb75adfa1");
            result.Add("hr", "eff429662364936d316dd615df7d30caee71ba41943a6a11a59badfe2d083147e03e6affb04ac225989060ea0bb1d4397b4dec72e11ac16cdf884428598a011a");
            result.Add("hsb", "d5b73d0cba8b02bd83eb2068715c6e972db4fbf9128809eff9346f0cfa787d1779a4b27f8b361184b9b2297ecb7593089c623c4386e2dc2e0e8ffa999eaa3c7a");
            result.Add("hu", "9dcf2e62c0308f8d3941bbc6fb2d11071c678757ce35a7b7af470bf8fb4a8d2adcd01bc365a664a033a1c6340b5f1a2b8ad7e499f5c07bfb0067cfea686042db");
            result.Add("hy-AM", "87f807906c27f2b2b72dab1c5c17512bfa11719d5c0f1fcdacdb5c58d4c54b976ee4ab4c226c5020c4f87b07de565f081534ccc6f2a89ac06031e5cac387c719");
            result.Add("ia", "2193c7bf781445cce2c0debfe677da32003361e8d0186203d264ce38ed061bd454cc3dde28d3bbd3d1d1a402dc72fe0d311246ffc55d8929dcd33f2f3e0d7c52");
            result.Add("id", "809a7a1e028bcbbdda6669533053f3226e2fcb50596b277a9108e1ca37402673ea45442d645555711687c102903f09b4dc5da187f28624d784c0708057da31ae");
            result.Add("is", "54cd2d847238dac396c3668191a038380276d3c1ba50f360be71922e5a0136f2a0fd47d10cc876985fa481da96f57a15d7fb5282ec2c11a10694a3372cce215e");
            result.Add("it", "fd9bf9d0507353dc92b68efd3173ac4ef9f2339e8d71272d69cdd049383f46d0e00e3ae62dbc83f4e828aab6e01ec9f22183e72edd43f4071d180d6a6dae138a");
            result.Add("ja", "41d4d33b114f4038deb0e0300a68bbfdffced24cbbff33b5cd4a4e65e75c9576bf0155cb60646a74698029971dc19886f0bcd8b266e1fd1dbd392b7dae597233");
            result.Add("ka", "016343a55014fb2f145c96de04b4d7232e05d85d3498927ca68a812b45d8dd73cbff95f74cbcbf6b81a43d62fde7d790bf62a95d3f1f35dfddbf5bdea02db32e");
            result.Add("kab", "40490f44f2d582dc1b16ba663bed0775e14dc9602d93ef6016cd17113664121532e7d1bd6988732dfdac6a2b1fd6bc2f51ec92aa830177ac382597607bb1c530");
            result.Add("kk", "28734ecdef5ea88e349624d0a59328b95f54dbb25bd8f0cb2c2474e2fd2ab5f9f13d6cc36ff33941d4d118401e494724863365962860fb6eac52f704ee15cd8a");
            result.Add("km", "501a06245b7a1cbda4fb39068902d27754180c5ceed71d26409ce00d26748a7b1cd23a2e477a8acec051f5b0d19e2a88225703ce634a3829890a3a321dd49e0a");
            result.Add("kn", "e8702d5db787b7ed6f2dd6a475f7621d8d916743fa2d6cf4edad0e2f230e8c1c6d419693c936329e9e8b6389113245461047885d15c62bf4db714be8ad6d4320");
            result.Add("ko", "001b4ce7d5c0d76dd46d2308c2c180399fd1d9ed37e61a46de63163a53dd304b6cdb6cae0ecd44b1d8328885ad01bcc709404b0e2a683ff4626915daa3a78417");
            result.Add("lij", "5a991cb69718a57f609a8cade2ff822ccef192791768f319a5680e2da94cda0396d4834739666a4d15ecfc540573436a574fdd141e518b5acc27f237cc566e66");
            result.Add("lt", "e913294d9cc7cb772241e7343e2f7e9c38c8ab2678bc18777eee553040394cdf527b7f1b939e1f8e9381cb555be98328ac2674cb58dd9cb66495fe9cbf034ea0");
            result.Add("lv", "ae7384ec039e87ed1b4c0c1f00adfea281cd171217584d7e68cdef996edd94b013da845bfb7aedb5302f1829aa526f8eb2da2464bfb03f153e73ae244db38f5e");
            result.Add("mk", "39b97d7739bdbd307a42578c2b5996ae06c1b7761d69186c46836f5c9a3d32156d7520682832a6424670fb1970e8a2e842ff72b6969606c5aec7de9941e21e40");
            result.Add("mr", "314530869e711205ff8dd1d1d7e174ceeded0b4099dc4d52c34fae918e41a189b936cb309e29034e3ebedf9287962b18600918f936e60b8344f3fa61bae54e8b");
            result.Add("ms", "3c99528a8e55df70097ae0da13900aa747229f4a80e3b723981187627a71536f67c9618e1e792bbbd95eb0259213edbe8a4fc907fd9d4bd80703192d610ba0eb");
            result.Add("my", "dfe2963c832818889760207dd8d6461603c9429a0d75e59c0534de58bcd95ee536018d78dad571ae4f170f8d4f2d2499f79e87ecec477cec8080f9b2cfc88f22");
            result.Add("nb-NO", "971de8015d1ea9a08ccc45d7e855e2720c4b36f164b80a13849cdc2b6f15823c1583a5afc9717875165f86b8e92efb7ba43ffe6b86f24880a9acd816a6e352a7");
            result.Add("ne-NP", "889eda1b44704c4771dedd22e51c895aa2a7c49ed32f7a85fc19d3125990853ee16aaf4f74ab312ec76fedcb910d34ad8ce2934ce3420ef9a632cd86ed1b515a");
            result.Add("nl", "822d0b9568217cafe13e956a08fed8545638c9382525cf0f65c93e5682a9cd9e5d7b7636ef5bf92eaa5ead674da069beecdcba910404c620312741d9c4151942");
            result.Add("nn-NO", "6c8e3c038866242cdbfde0d3d07ce2cfeebd04aa183307f67d035a5476f59c75c6e9f8027266fca93913bd98dfb5a32eaa185f092fea230a002172298cf368f9");
            result.Add("oc", "ced58639388ca33cdd1320fe672a9e8b5c491d5cd421a5326e05e198b6ec4f47431468367858a0968301371522ef84549f628634a6a56cc8f57b8ec673d38692");
            result.Add("pa-IN", "e75a6c8ab24a66a2cecd84750e60ada101d93cbb90490f32593aead332ce529900537333a13488301a836a8410286eb9647c9d1906477f52c74a0fe9bee465b6");
            result.Add("pl", "84d9ca70b2466306e7e2b211492ee59313b425893e99880f98272775eac25877c3aaa5a3c127a0e4f482d0604b35fdfe287d3010ec7b6bf9e61ff5cac760c930");
            result.Add("pt-BR", "c72bcf546bd5524f82905abc3b62afd996d74c61f466f310ba41dee9c495882fa5bed4cad9061dd57cf2a19c11b0037a70223741faa47bf56a6be4f1923b0e92");
            result.Add("pt-PT", "10bf478c46ef25c6f800a51ff0404917ec4fcbe163cf4dc5035258ad96867f3b3c6ef93e6202e0bee5381c9bb9bd5953a6f0ed1cd52aa7b24e00d3af22536284");
            result.Add("rm", "c088ba0147decd1ab628306477e0185712dd8dfa933f90bb716847752e51c04f17795c286ab87cdca11c6bcbda1a70f86ad3507997dc4d962e937928e8254f2d");
            result.Add("ro", "04f8ee193f9836019fa10d00f1bd1f1d93c18032c1f42ce17b3014cdb091a525593cd28c424c74e4e9be45063b91325a177975a2f72a5bb264da4896a8714444");
            result.Add("ru", "cc351bec9b8d7995aed6b5a30a9385ed48de56d2eefc859296fbaed7a94412578aa25140815d3e7602d6dc1c6ee4a024f6b94d9386293acc1e73a70240c1204a");
            result.Add("si", "4561e441ca7a77657bfc010f7bf59f705e28e97119185eb39c3d584843374e9d33f96da448825111fa615305a99be208d8ebde9d014c42cabfc4cf49744f0793");
            result.Add("sk", "d7a673c45f1b8e690041f9337234480bb720928ae4aed7967111c2b50b19cda555faa57863d9ed4de22e246a7541b0e80c8a72d57b7bc4faf451129d90edaa9d");
            result.Add("sl", "8f3f0f612a59193eab3d210065048faaff8cf2066424f57c9aed19dc7039e23d593c6ea0f2d6c3c4ccc8365e63354481849e99d9c4ab0ad284355d761b97d089");
            result.Add("son", "131af6eeb2b7ac27fbcab1df167b61b65a861bfbe3e58c1840ea44bcf5f341990dbb88b8e447763c55ce59ff408d30f83e8d7dd476a703f0cc7b1b74241701bc");
            result.Add("sq", "04fc356d6960f8ec5fc149c39f8d573f65d0328b9212f40a3f59ff803e068bb95295d6ea85d3334d343a49de235ff0e9fbf0733f95f2579c286e88f7512f2acf");
            result.Add("sr", "37eda95a67b12b571fac2ddf6a39d5a78c1dfb06ff7c84943a689a0f734425bbe100cbcddd9d8b4a3b25bda9369dea8412248ce3e59fca345f19ad30759f9716");
            result.Add("sv-SE", "8e1668bc187afddc40f44f8220caa6aafa39e828ba8a3f4a23fdb23ab8e4d7a9b81bcfb55638b5032fbd5789c5cc4698fb10a75a4ec9efe5d93330babf56274f");
            result.Add("ta", "0ac8dc3cd9f8765816d7ad209cfe1af25682b2d3aa265db5b3c895374f774cb4679b9adc7e558476d0a8bc49d5b548064f50adb22a29489da328445f241cb26a");
            result.Add("te", "7de857296f9e1f73aebea80843bd77b5a176417a5d5ec859db2b5afbfbe150f540423a7c38b994ea7cf20582b95c28dbecdca42b54625aee5d430966eb8cdf33");
            result.Add("th", "e65eef157e8448de0c2a5b4f2fddbd5974cb623a488a695ccc626c9488c90fd7cf075560c46a981a5ad50258a820d4fc2e4e98569990d212388e76b8909fb34b");
            result.Add("tl", "5622abd9442f0f57adb2b8009df52b81a4813029f493fd092c7146f85939fd1985f9019ff46d0022ec86a0b42b4d8c9721eb5946fb7832a0c2884a0b7b8d2c44");
            result.Add("tr", "5dda26ce60d11a2f636067bfa8d0f287667376ca70141b2899539d342bc245d5206b54cb92fc0b446b258b8811db48eafb38db4f82e83e5bb63a66b5cb287ac1");
            result.Add("trs", "19bb5371b09476a433be29fe9dd31cb1f93953a70307cf10108bb9d2b7757bb98926b5647132ac9ddc65692a4bee5ae1ae5951a27e0942f5032a529e5e982150");
            result.Add("uk", "a1b6bda374f3b77ec254bc2ff780ada14446075d52f8456d1b8994088f2dc23c343f846237f08ce749521d46ad70aa1b0dbfbe86c41b05d392740a1af97b821c");
            result.Add("ur", "837e94a3aefe9a6703952c88abc3f97f1a7af95489e7bf4d1abafb4144c4ecf3b2c54428f5d71ccdc158359f71e39b150b9775e0e89a3ca209f80a6c2e4c4940");
            result.Add("uz", "ff0efd8aab83a6efdbb6b7cd98ce1e2b857afab2f122728d576a40d4809a5ed60eb24834f85daa581dc22ee75f1ba68e87a00222a77deb8dcce075884a04d009");
            result.Add("vi", "2ea7590e6974f10a3c07c066e70ddbd704c0242225cc612a6d609609e5399579f729519c7335750eb080e5ba799fac7f4245d86274ebc36450ccae200a8110e5");
            result.Add("xh", "e32d8ea80957729bf6c68e37c543a4e407ab8f6788fa7d4cfbeb80fdc8c122eb41e6ad5798befd48745c8235322f98010d902ca01398cfb8695da6fd1fa87284");
            result.Add("zh-CN", "61116d5456913f0074697cbcf16cad64857791c2f08f89597af61c5ede528acd61d64f987234458e23819da46e41a204aae42cd04c7fa950fae0d7a074210a3b");
            result.Add("zh-TW", "bc1ca383ff7798cba3208bff2302d1ade211b8174b876fb7725212e24aeae064e8f56927ff5250699562faedb5a0de9409b155e00792f8dea85569119cdae90e");

            return result;
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/81.0b1/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "7ebae270c3fabc95988e8613e81dd9ddb51507535f0f768e61a8ddf464046aeacb9283c6ac6986a2f4f2c706c3bbd6dc905c83f67783b79e04e45db3ff0a4abb");
            result.Add("af", "140d00fb47b320557c46980729b94cb1c3a186a45f6ef5fdcf21844303c40f76b069305da82d50705d96ef8376a3bffe5a5e92d61ad04eb0509bd17a2cb4304a");
            result.Add("an", "7a3af0c9443e22619237a2e77e72d754e94c9d7e0b2a3e45fbaa0fae52825b40cac994018729b663a70c77507e34ba3febfab02289ee7edcbb3f963c1265e908");
            result.Add("ar", "ae65a1251f7a8fafd74fba2450f532d865df6c0b0abaac8e358196bc3261d821174751448afd74434e1ac369cec42b2cbeccc4ff3acaa3235700c8bb13c437df");
            result.Add("ast", "437febed054ef54b58ee9e8f33f7cde1467868b72a8c0b4a373c82a108ff4df8e1701a816bb87897b623e667668565cda13a7a5af891f23c4ddd5f9afeee8db4");
            result.Add("az", "27494b4fc7bb577343336b2e3524288b6ce38d878eee4e70ca3611696027fd49c386aa59accb12da3ac98f0a839c8a10e61abe910b4ae294c71bdd07c67ebd7f");
            result.Add("be", "79af591605887459fd9b65dffaeebfe862e4b11ded79ab698af8c9488dd497a4882566dfd41956f29d9a3619b493c68f1b9094f9b72a7f97f664f55b85ec7f36");
            result.Add("bg", "785be740259aa155d918383a072e234c69ecf95e9cd4c862faba28667cb4a47414724bdad0bd6d4ad43865abde6011abd32e3cc50052d4fcc500b8411cb3ae82");
            result.Add("bn", "d2ee1fc6f6ec295d5dfa0561b91b7dc659023446d95c8834f3184b2d7c7b044701e00ca36efb2581a34f7ecc82182912520a18e1b2fb1cd97742f1e8cba2bac4");
            result.Add("br", "2de8830e6487a8484351672c3cb9f5d3e5e9947e005b62d4bf0492a5db84ce0da1837826498222c265c283cf17beb3b4499ead54429b79e45c98f6a7864be689");
            result.Add("bs", "0dc39f281f296f359b2b7f0907796535a45ed8456aca13fc53d1d2cf05f4d3c10d109f12cf9701473007df911447f75ba172f07c1a986bdd3893895746b062fe");
            result.Add("ca", "4f25dc2d32a0de480d7117df5d6daa94a8dc2396cf22a03a1819542b68e0fd8292f374dc2eca8d08d8aedfca85ae876aeb12886f72a448c24835b25a07e6cbbf");
            result.Add("cak", "eec7ee4e00cc0121ffa870b414cea8d1c738e0ee8777b173f4d0bb7bcb0b49dde11c7bcabfc21fb663d48b4b1b7e0e0528fd94c511534f72c90218238035b277");
            result.Add("cs", "ddc9b9a62562ae312fc4af2503d8797a0a54ef6de8f034f54084e13aedbbb393752eac00df2cf29b3ea10ad2d5a87f88a9039b361ba4f4ea81be7667c22ffd02");
            result.Add("cy", "fc09161af067ff10254412662b1da19339ece1c828b0b35b50af024c78cd040897631f7cf1bc601e590b7f2393681f6ba62fa490f4e9ae5f2b6f6e74ca1e43f8");
            result.Add("da", "4f1fa67769cf625b11946670d4ce7bcb209b7043b86b0a74b7542b20f94a11b17cf00425dfb78dd0bae199c142ab2c9c7a2bb7b7f334f32d1144fbb62fb6e3cf");
            result.Add("de", "97e0ebf2197e239f93ac7c3530a12b266d05dd0292b00781d827e7cbe978ae04749cfb3291e597d3a5c5de154ba64ec7f0419598b68442e8f10e05c83a747693");
            result.Add("dsb", "3463bf98e1c1e5aa5017cccaeaf3dcdd4514e431c61e6b5e5f5b59d8c4b341a791c73393698751d7fc0df0ecb9ae964e2b2847f14f63df16d5bd763db18fe42f");
            result.Add("el", "ca2e82491e9e249a8c40c1cc2c3b40b40a434a6fe6f8fcec309f0b0454f0a71c61231f49a4409d17468a4c83185d3f6d8d4a0ddc2d826b0d53c17fdb6c5c92e9");
            result.Add("en-CA", "67c8df4a4bf15c806bd76abac689f093382e23702439c1409c48e5e0d6548b6b28a5bd2691c1e662340bd381f29fbbbab0812378ea773c6c197563086c761317");
            result.Add("en-GB", "b14a31001f16af7c2c9ace599c97fc0a0cd76642e50dc95c46bdc136263b3067d1132f9ea09750d0f849c8f7932276c3be8dfe475b298b033403b1d8d9a00ea3");
            result.Add("en-US", "bafd2ae106ca5f8fa032fe2190e24d9903a3def0046cd2891dfaa895cd061678a3f3dadcb8f3740debd8f7b955628f7a87a5a0859560ab1af230fe12a208c05e");
            result.Add("eo", "52e501a02703e57bae437ef75ffe6a8bc43487f0f60391c37e506122d4eb46362972cd01051004873fca0db3ec329c2d4fb29d06501406140851865899fd5f88");
            result.Add("es-AR", "60887006696a646d941af0214f44d46597a81628fa94d8b6d553dc1839e4bcc7fc7d813d819dd3d4b5de7c1c1f8c645089a5d785d2e38292acacd60b5c4c6e85");
            result.Add("es-CL", "a5e1d8e91f3cec4500b26328334af079af5bf977548e07633669b709c9e5baea1dff045b3b668718dffce86b2fa0a0f220b3c2bf1137915870f8e8049411dcbb");
            result.Add("es-ES", "c94d770e15560f19e5a23cdd02679b07d263d4ddabf5b39dbd4c4028aa89034f6e33abbfe3ab8c01aaceb34d622b98bc061e2f011e5b0224280c8a180610e5c6");
            result.Add("es-MX", "4cd65ea4e3b77540644e8974a589722e80a2a37a4ec4553f5959241589715600f9ce61da50edd3f7dd259e15d1bb0bb42d5d50ebb286ddf0fd05e711ae12f0e4");
            result.Add("et", "5fda17082a4887a5497f45bd3e7a12a77b68a048b8a4e0089858579eadd089aec03cc98c9c5cdf5545c90b887d8fb7994c354dad68ab78aa58b06ec8233771af");
            result.Add("eu", "c696eec5d12f1fdaa79d52d9f4629fc04d2c61198f69a8fd84eef4d9d9f711f51b69437607feda59c2e2ab65a64735c7f202ce12e01d2c0a0d146611e2240956");
            result.Add("fa", "51a37dbe78547c70a5cea40cb815f49e63b5d8fbe4b52d353ae0a79f38cc4f097c8dba15799f3960b9ce885b7105f072ddaa19c6fef9d9d1629ca5419ced2897");
            result.Add("ff", "e2c4720a835f13c8aefcd75894bac2b0fe776297c60f6475334c49ca4664cb01aa9a8d1652f5581eee7056c17f5df15434664c535239cf9ac482192976c1b1b6");
            result.Add("fi", "0ea3bdf6da8ef4202826a27431aaffa01deeafaa37190cdcc813eaed897cdce779e25347d253bb671b5a0f5d814f58cf5ee253b969f30e118e8f9b0d9328da65");
            result.Add("fr", "1d483b2dd5443552a5d4995fb864e5b383686e36dd50b664beaf9e7c467338bd623a94295f8e896b6f08e8c0b7eef4cb8610f39460c9dd0e85067bde4c7d0f4c");
            result.Add("fy-NL", "cce32cfc47c64a9170bd4d72a11c8b6e5244bfed9f13d7015ddcc307c3d6d3b15b8050cd7f588d95679ff7e20b9b511d7b4e57ae7a25a0e693761a31116eb6e2");
            result.Add("ga-IE", "02fbdf475242f6737abbb0c9ffce552dfd0fc69b14b0fad221b7cfb1792d0b77fc2772b0e9cc5b13758e31e3790d491ed360b45988ee4fd895fdcf414e466087");
            result.Add("gd", "a8aa545d4cec6411f9fcddbb68ded13715afc672126fe58ea3b9b43b17b95737c22da7a069e14729e86e0835e843ebb908093c91f7293587ee5e829d838bfe77");
            result.Add("gl", "0f1b790dc2d36081ecefe23feb45ecd2ca1d9d8b1c3f2b69ebe295b3e4091129724990cd07088706be543923a994ea8013cb90dfc135923b80f95beada2a1833");
            result.Add("gn", "b85b71cc972ccce48e4c976c75f0ec478ed0163006708dca70504a5b66bb1f0f229c5098b4495ad163fe11c84aa9e7a1f4856c21ff9117a4eeb675c5b04d7e4e");
            result.Add("gu-IN", "e13cf9ec616e5d9cb695db57b9703781e9037871c2e4dd88b54e1cfddff64da4d75c76ceae42f77e029360a862f56102167e1f2d93b850f373553bd2173f2183");
            result.Add("he", "5beb93d00f9b45bfe8a54c4ec979270d7d87a0a677f94aaa0a8ba84075c6196850d85b6f95d116d919b223a20f2c61a680c73fbd4798e52f93fb14a83993c66b");
            result.Add("hi-IN", "1c44ee1da0f109235c236656b4f697b289dac1bdaee1c97a0ab12b1987a03b3165f0de74dc7ce807741f4676a530f1728c972b08632695ea25852ca45325ffd1");
            result.Add("hr", "b9f2351b61c19decdfd2bc7ac9c5f368b6cfe35427c36e81e1f9320ebbce1dd1d8459aab3e5ab86aef13bf46839abf2a30791988d22deb15b2cd9634ec00be45");
            result.Add("hsb", "22e002a520eb239a511f32941ac3b0786c01c6347816a7e741ec259d0611e05754e20e467ada5df287c28d53a1c2361da4ca4e7c177751087fb9769698b16910");
            result.Add("hu", "00be4891d7541b49af6e5a13d3605779054260fc4c639c790a9624b5cee25ae308df34765b72d943d72a2e14fc6aebb69026d12dafdbdd87ea388c2842c076c6");
            result.Add("hy-AM", "45c2d8c2c68a4e2bba37b71b93a659a8b610c598c73900f811ede6dbe32d2f414ea32b90ba25b878bfd94735874a3e328c39811fb38be592496907fc47f8499a");
            result.Add("ia", "e724130bdaa6e755706c7c22ad20e91d9f2aa9d8f349a10f5fc27f95e342fb8baed0b6523c01549934fa7d2362a8023864a76142217bfb56b3a037103b7b99e3");
            result.Add("id", "548371e56bd97eb547444ada31c4c3b7ae58890af8a1a95147f902464947a6b331228fca850360c29a597afcda707526c314d6f13d50874fc895f08f79786d9b");
            result.Add("is", "bda4089fc2e8b90e12faaf59c91ba520287b0b0c71953a18c713f13bd30bd5ab191ee56e6ccbf75efd82cf0788b83e272f715510bc9cfb76bed3a838d4e96af0");
            result.Add("it", "1fc190a31fcae70e1aa4f624bcc4ba0f957d9c082f376f41ffcc06246184cf9728a78c889c5a2506ac7e136c679e2d7a8746b9eb7bd42da7e7b5e4b681d3e85c");
            result.Add("ja", "1c4fd0f4a5c78185c18561644f66a8d8d2a0bf8be71f66ff5a41713b4c1ab5a17b0ed41f78d5e97cf88262b2c72e3bd87f16dadddc1a74ed421c4228402512f8");
            result.Add("ka", "9d19f72c8c3046c7e1911528403ab89de73c43a815fa4e9b7104445d68fb0be3b0e429e124710ac9e4cb80213e66c3292f0f48d515bed489f353712563255815");
            result.Add("kab", "23f1b84df839a079279f99c3d5c2edb4b9aaa1d1c0b91441945c5aa856ec00d44f77d1d17c8784f0163b0514ee643db6b44cfd026729c5e30e63aec9e5075e96");
            result.Add("kk", "9a528e0241be084557ec0123925f1dbf2ed6f29649f5c51190091a1d6ecfc07a8a7b001c600dff5d39f4d24e7b84770ac80a168fdb54a568f7a81b3c605c2b1e");
            result.Add("km", "e3007b6f35e8437f57e6b655d7e943f7f4351473ba21e8e277f7dbc379ca31d0baf4ba3572708231fad2adf68222bd0ddc99e538ac8a1b330ce22aedc01518a4");
            result.Add("kn", "1cd6d642cdf757448e3ed7a54e1d5cc6b57a0fd3e6f1c5be6964c581977d6554b761db5f349974940ba7d4c2dbd0ccb23e8b87c4856fae1678bdcb37270f878b");
            result.Add("ko", "cdf4f3b16a3b442067c4a55bee49205e9f81aca022fd9beab64552bc6718793e6d51ceca0ad76f86edb1a78352c51ee1ce6c2f49af2eab1c486e4f40f32ea87e");
            result.Add("lij", "91223642da5d2f5693828432aa17c72ba54127420461da2a4eddf20caf100adca41e7ce9ce5c1141a66b51321a288c450792f10e7f509189dd8dbead89442799");
            result.Add("lt", "0c9647adc1df8be551c6278ff28177b92a14217421bf0e7371f1378947e2056920ed7cf63ac78d92c5cd210e2dab1f519df8b488e0f18fa64777377199b1410c");
            result.Add("lv", "7d735b0bd0e349f476d8906e0de8418e0b8f144c3d5881fa8d6b9b04a36b35087e11541ea243c8d53bf1223e9221f9ab0e22427e27009b5b4b664376ef776353");
            result.Add("mk", "67332316284abbbec35fe359a0839c03f8163a33ffeee9414249e15f9fd7a4ee95d1f61b020bd481cb3d848620d9428799cf4d33de286314e25851e429a77f92");
            result.Add("mr", "cad7dfc80775cb499949a72f30de5746e2fe820d2e5aee71256e4458ec7f10d524bebe7429fae2312a481ce7b5d6b468df8e000832a5f86a7274adf360cc7de8");
            result.Add("ms", "ad2dd883a2bcd1d8984afe29fe802348d589d113cb1d045c31aa7ca50ee001805f63c26e555e38ba98bc7aabc5af48c107b28b5c462dbfa6581ec7bce8e10c63");
            result.Add("my", "0f80fc03530f0b265089181adcda5645eb1df86d95fa9ac1aeee60cceca4ca626ff787d6c4d69d87daae1f59a06d128d056293b9a51f7390a65d6fced9ff471d");
            result.Add("nb-NO", "a7d2fb3040b8e7901a1267e85fedfab396fbfe7d7f911f9762d761a66c5df210d5f18958fb35cde26d03d8f2f36f1fe4764b58cf9cb0087c14c50bc75076002e");
            result.Add("ne-NP", "6c4aa96bf1da308de62cc43b1ee72468639c7cd99bccf559676aadb0dc0a4dbb9e5e823a2c73ec5cdc7cf301209ac1dcd99e668b335d7b566657c72f446f5715");
            result.Add("nl", "76c7f4c12d83d29fe43395370c442f1d4ca2f96a97a32621d4e589a961af0b35f0a2a2b2a8ec7290699a97cbc0f1e440efb9701a31a8a0f3cfccc19b93ef78f9");
            result.Add("nn-NO", "611c56feae6f3fb2803a3d61b35fabc320c58260e55b405042f159f9b5695baf371cefe6512f992b0c522849fb0b02cfb9f787e58440a691f22c5e0aed809dcd");
            result.Add("oc", "ad82a162d0584c9d90c7537cbdca22641ce7066057d9a16e03cf7f094c83559d13d2f83a3834963baf2472ecedae3a2a3b15747f269426ddd2e6b031eeaf28ae");
            result.Add("pa-IN", "ca9d7a6f0f4290feca1bc261feb770bd81d7835a7e9e21882dc5500a3bb1047ac71348257faa8aed87d2c29e99ce2648af1821eabd5f515dc07542b268e10aa6");
            result.Add("pl", "200bad7b0b1259f8e95c6ba0d8939c94408eee382bd7f871b691dcf8468397b5a0a041b6df9fab599f7ac66cdd8ca9687689baf702a163d1551bd402402875e6");
            result.Add("pt-BR", "24951b47ae209789553a42ea9042e37311365ca228d9bea7889c8aff4fe6818ab76de05a430ed80656618633640288b4989ac8d44234a2fdb9f8f2f36ff02522");
            result.Add("pt-PT", "0ce896aa9ca8c32564e4c17c05d30ffeceada4f55470b7c226018c1aecd7b3f0de812348b5fed79273fede059d17c6df00037469f201c8a335a56a30ffafec05");
            result.Add("rm", "d9bea2e1bfa71c6292344e2630718c212b64feee9c533cacd68f0fdda38aecac109c9ef6bbe7a3865408d7b6f288c5ae0f5754af1e89432f78f0b6088c363db2");
            result.Add("ro", "87fe7caadd39be93687233add26afe185b17eca713edc80381d3fb3bdb376e35aec704f3517e3e95e91916e10dcdca0218baf9036cf0987a33868da801a066e7");
            result.Add("ru", "e4ffda203eaa704bcee8e0908d3ebfc2c6d8ef828d7f6eede91d94da0cc9a0346b9e2c8eb87679bc224f6e9c5a98296a477e77df0c1c835d201ccd81b2a37c9e");
            result.Add("si", "5bc2ae774e7da189c5bc7289b2499d67fa390ae57cd6e2cd44f1d9d3d7f51c8b748eeaeeb9f5fa72295876c2739787dd50f769296df8842b7c49ba6a1f827a86");
            result.Add("sk", "42ed8a95e63d33223a9e67e6235f7d64aad7d93142ea0370faabf87dfd8ee8ffc8c127964b207be750f91ca203e550802a039c288e2796d2f03d84af5e28bd6b");
            result.Add("sl", "561fc7bc15c224f79267e9337f1aabfac299d728f9b767dbc202bb04f2954dfaa5519e805f4fb70b1acd197f514ddd6c6f15a2d489d97aae91200952b9123b2f");
            result.Add("son", "75686aaaebd4a14da3b2a9628ddf2f423266ac9f4cea30e06579f5fb08071763de70e86585fa4e21f604addf295c0fe6b0517af850d349af79cf3d33a510001e");
            result.Add("sq", "5bdcab4dc3ffc85fbed20c7a09b0590182b82c3a834f14792c58432f34960f09048fadb2fef7f4c22d31669225e4896bd490c98b26488a73bb671e99e2317e2d");
            result.Add("sr", "77619e2fd010ab9d5136535d947a261c00718c45868ca7111f7fcbabf0c1b4fd552c24efad55a281b04984803a59c9473dadb3557c9668c7f96bb6d6ff4dd385");
            result.Add("sv-SE", "0e31bd89afeac3a071d94a534d145ae0be2d97d379515522391da77570e1bf4b7149a4bc429d7f70330c05a4c8ebc27aa83936a82ecd53318a1ce787e58a839f");
            result.Add("ta", "8acb3ab3e686cb0cfb1d25aceff1181f58233a1108a53fc24cac1fd68c21a5cdf0ddad626e49d0d1a4a9f6b93801d24d70ae4921dad34eb15afb636c25820003");
            result.Add("te", "73dc33a2f0aba6209c99cf36d2baa7efadf1b301f8947cdfa0a0e7484c25f3b0f1fab8fa073624c004743e709b1e2cbf8106f20803c4dbeb66ec6e2b506017d6");
            result.Add("th", "aa91a0bfdfa9d649873b8923e17df8bbf1d73da759488a9749370a53187515d5900e5bce71df923922d5bfa523cd676df5f33d06bf2fc6696821e2939d433c97");
            result.Add("tl", "5b4ea2f3851cefa8293bdfca92a79a23b531a410f7113ffb70ead17e9db669aeddbe63f0e9363b6bb9262a07be69929a3d2333a012b650f1d4831612a9e092e0");
            result.Add("tr", "f8b0a81432b2f5dcd172482a9cd7f4949bca0f3442563392f5c9e53bfc894b0c41a8f09e7a4f8b3595db6edebcd36a1f78ad516b25e1f888db16228dcafe8f73");
            result.Add("trs", "9df0570c4968142e8b5b2203c81a1ef4ebb7c0c704cd34431d35a3a536751d8a9cc112730f1761454bd7da249cec5427ef87875f3fc528b1fc4b5fdb74f0828d");
            result.Add("uk", "31a4b56c28946f045e30fcee39a2c0e955545a5eafb3bef8db157fa9d4827dfa1d95566be1492ab7c784d09f32f6dc1cbee26f391beecec8e6d8375ad8ce3948");
            result.Add("ur", "c188a238af05003eef6c56c1ac6732c39e145ea8bdf0ec313b080ae1667aac530727b20cc81367899e608c490ecc61f99614692d24be35d1d082661f3c6a9a63");
            result.Add("uz", "7a41cf4249c1890b3b3cf8bc5efedf6dbe74cef08e3bf518455c553268fb10023a5b2f08c60d1260419b04ccb77d2ff7a890005ffe0edfac6198441ce6cf1936");
            result.Add("vi", "9bdf0b42004324e6160ecfde69c55c6e6a6dfca7ea820af81250cbde737a54cd5ff1d959957820ec29236f16f0168d3f0c48deed4e32b8b63385186cba8efd32");
            result.Add("xh", "33547a2be530a4ee94a04e2729078049a0bf6330b1c3254da9f2b179cbecdf3ed2c437c76097f8609d6ff8d3f574d9f0f3c185b54d4d420c755839e7b29e9c0a");
            result.Add("zh-CN", "ad3b4caeda831b31bc1db3438e0462d9f96c5e6616a187ae8853e5c0d59a53982acee73023341dfbd35626b6ddd68c6beaf3697f621cf3efed660a2fa876e225");
            result.Add("zh-TW", "b7d0eaba3bc1a9fa3b5452d860c00467ae3e0b6f712b2d720bd73cadcf24e471d1efa7cc9f13325d5bb3072149b3c05d5e3f5240fcc2d1c9f2188db8056eb86a");

            return result;
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
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
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
        public string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            List<QuartetAurora> versions = new List<QuartetAurora>();
            Regex regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
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
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
            string sha512SumsContent = null;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                using (var client = new WebClient())
                {
                    try
                    {
                        sha512SumsContent = client.DownloadString(url);
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
                    client.Dispose();
                } // using
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
                Regex reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    //look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
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
            logger.Debug("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
