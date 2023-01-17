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
using System.Net.Http;
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
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


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
            // https://ftp.mozilla.org/pub/firefox/releases/102.7.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "06c000bcb7ea943f7a843190d96fb62c71ba965546a27d9e4d6ef892b6a6dc9a2ce1777ee7f1cca208a908037e8ee06182f5376bc1419d5b2a0710738a656a8d" },
                { "af", "1307a0ffe9389232a1f30572a729931a2ff671174f7fb0ea9e07a44ef23de37461bfac5faa98a1e00519353ad38c4fa47a074e2cb67fad3b3d69de1fe6f570c0" },
                { "an", "d1226f80efa31a8917fd6e2539e6c925204b0e786a60f8aac09d2dca1caf5deb856364b215c3a01f8cbdeba3a2dff6ae46ba9b493fdfd51bfa1a53629ba35d8b" },
                { "ar", "1c084ea3dbaa98668219e4ad23704637a494363f408fa5a1fd9073e362435148525778eaf4f58044657ecfe90c6ca037c5ac59bdc3c125387bbb97072a0770eb" },
                { "ast", "625a5104536e5471712a2ac9b8b9f21ef4224c7f6340d0e804736794be0f23e174934ca63e4a220d55d8698cb12ee08ee6af0f7a0551cd66fb0db1ef0781058b" },
                { "az", "36316690a86e611588c6a53b49e7e2216fcf5eb6cf0e8e1a356ffab70bc8078ea738cc697c937a151878f2e5d8cbc706743161a4da2db56b6dd49258222a5099" },
                { "be", "c5984f033a29cdcf5ebb9b15c02d1deea252648f3194859bdd67c98cea7d7a4d39169ed48b0c0aab5a19e357eb8df1225f4d14324e580a6bedf73ba37a5dbcdb" },
                { "bg", "f4aeffd2861306387fded2323c36cfc292e2640b1635360c44dbab103d507efaa426ec7d47f78090abe42a8017c75914e9d75ab05d3f906ac7f87d2273aa0fb5" },
                { "bn", "a6a756c8a344e8baeba5f1b186eba47f256077bc290c2c63ca56b2636405455a23a26793c4a4189f5e1efdf72c51f275eb1be05c2842b579f3adc85620b275f7" },
                { "br", "a4e2aa15f4848e86e54ceed96d9e72f0f8006f06f02a3bcfdf8d618f0ecae9a536cb5472919d87566a0ecedb020b194cb36813b36187d9ce10be97ede28a5768" },
                { "bs", "3e464161f011c5e96c7cb8f597c405447de20d027174fab0756a1a9c208070dd395bb5697b90de1ac883f71ecb11f2631402e78bf1b3b2d81fb4eae5e009e6f6" },
                { "ca", "c7cd6929cfd13c572a9764ea044320bf31e2c7810709ea0c71123b8dd7d31bb73e41e9883a186606463fd37e6aec382afaa43cf149b88daa4f7f13ccdeb619bc" },
                { "cak", "3f596c0d685c249848e35be08a143830fefdafef8b263500426e4ad07e6829476fc6d9c01626e08ab8ecac67bbcc2e50907a52c7bee159cae322034d673fb09f" },
                { "cs", "46e8238b32a7691c8b598a0d959ce3015eccd656cc1f7c5151f0c58ae5471e10cdad43f0d2bd40980b919fbafa1e35f3621d9a3af587422e82d273c1d1c379f4" },
                { "cy", "64fe6e1e0ddff225fc0df70f2b7e4880c983f465fe31c83052a5be937e598007f93fb1562c848b7095809b4012ca9947b8717b0afaee1e1a6a7d054fb98d53a6" },
                { "da", "237068599a6e6a5b28d4ee08ea7cf423ae5b1d3355f6c268ded014d9c2b9188c599e22214f62c046ab3fa16a58c1d240df25dcc7c990c5cd65a06c77be164551" },
                { "de", "8feda8ca3d13dfd06328aa0a3a98d6dc391844412e7db69e869f290875f5fe5014306161b0b173c4daea03299e947cc09f33ae08938850540e0af60f8fa960c0" },
                { "dsb", "5d6b4fbf284472b2bae2545fdbbbb2b4d90adaba0ec1454132836ad2a914425f9d6f9c06f76d977725deca824a18fd940d732df59962ebb7c6b4f65272177344" },
                { "el", "99326f8b8ff266eeca270535b8c58389adc0b05acc9eafa81dc0dd57730fedd70d00e2b30de8dc55f866a0e8dd670f476e5591d3dd91350a9a579a52a5ea03c5" },
                { "en-CA", "1b3962f85e649f9d7ee415e3e4b266e6428b232bd1180d60643a622141ec6e9dae97a2f9eac4b10dd5d8e19b16dcf5c2aca507dffa66af63012372027f3a5762" },
                { "en-GB", "211482bc3bce8f04cf58b304381ec15c171d5957f9f8802cd8069edfa21618c3162fc885b310dcac36905aaaa0b6bbd41600b8eac26c7fd50e7366abf33d07e0" },
                { "en-US", "7efd0c5c718a4071b97ed74887e43ef464ce438388cd813114b254f3d7a4978c35cc728957eb0d16c05249dc5cf036ad99d6700c6b4bb58a60d0ce9a7e85d6f6" },
                { "eo", "128a11ab427334b40d2a2c75594cd2ead01fc6da8cd2f039d12bb6f736983c874208aabb78f8cf261af13075e63fe574f3a699b4f6c0a932db6d3977936f0a37" },
                { "es-AR", "97adec78dd99e1efa158a6318d466ec418256f8b4bc5203c798a99c160ebbda1c8d025e0df994697ea15d25c7df143e82af3262ceb1712e2815bf584affad063" },
                { "es-CL", "b529b99cc874e176e927d857bf119d07863cc1d97d85ffaa811b9a4b7c500bfd39349b16e2b58a9a65db34b65b5c92649c48bd6ed30e0ef0bec16b2c4ba9627e" },
                { "es-ES", "203018ff5c694478ea59092ae33259daf9daaf1631e15ca9987ab75f30f83f030ce26ca462d13425eeea9398cd7c9dde61b13409a24e98c7a0758b032cf8c80b" },
                { "es-MX", "bfccb76b31c20e4520a3c5e2e3a6fcc1b853430737e32fb0e481d345fa849e64bf83d0cbd0570e6d5ce6b0df0bfeffd6d034e74060bfefcf1b93395be1d52872" },
                { "et", "e7974cfe0907a60dcf88e2f6758e8f0fac6f6326eb39b470141eb225456accd23c3b383d1c3472689f03696569f2195e9c432a4332faa50460e7e4e99ce34fc0" },
                { "eu", "3549ec120db88f3beb402d50f0d504c31227ee101c0343007b2b81ca6e366c98d043a3ea17878052c8564f5b3cb674ea7db82bdb4a94b5dc2f8a020b108cabea" },
                { "fa", "3bd3606a9fb6b658e3328212425ca7baa02b8086de30d22a25925bb435bd0c75970002567ebaeba877e213ace5a6f14a0c834cc8a7ad79ac656d73ac6fd0f8cb" },
                { "ff", "13c4fa2ae9c2301f1d4af81309a63be22df0f8f49997d124107ea7b4060c37a3ae3eb692e556dddf53cf9b30737e49ea03243db01b6eede7fb7905aab1e36cbd" },
                { "fi", "5d2dfd94ff2179c0f51265b2c9137f94a7aef491ba7ba6869450aaa47d704525004daa7886b11bab3ceece9f430d733f40b2b8af68f53db4915a35f1b3b27c19" },
                { "fr", "2bdf459802980b10fb02b14058e19703d3687da6bcf0293a2db3272ed2e2e72c4e97b11c638006174beef2306fae8c07a4e47d2bf6036c9eef47cffcff6b3998" },
                { "fy-NL", "069a7def6e2d00177ecf1e84ce9c58fd2a671efd2d4b957b6eb429107654f1fb511286647781c5980bd326a2fff1b1c502f5b9d72b837d8eff3836a6fad8bc51" },
                { "ga-IE", "50fb33882095aa097641a2871045bb2df3555863aff6a07f3abf8b746b658330d7b204ead8e15a452737417ecb9e52df647e708e6b426d0c3d4fbc5ad4127f4f" },
                { "gd", "72ea36227ba491fe755bdab83541c3fe19dfd74628af7733a035bd136cf18ebc8ede1df6f953f3c3e80d2c6e8c536a4b1cf97e6801d1068950fa3b7f772cd7af" },
                { "gl", "b7652868575ce346e603e8b11b0721cbefb59bbb009b73051d1cbbf3168d57f65f13cd9bd0a15ba584bcb34877ea0f6b514e317f3b6fb7f6d19d997148cd6b9c" },
                { "gn", "92aa976d27d7edd83fc2dbf00cf90911e34cc100643fe8b9addb8be0669ce448778bbf2d29b981198bf52094e195dc958a0a92e42da1411d75ad84727daa7c11" },
                { "gu-IN", "a3eecdc5f4282cc4d347c85c483f3f4f7a777828776aff3b9535d8fc02a6ff0de1ca39081b07ff6c6bdb4a28f2943b5c4a1347a5b240e9311f42b3964c70d08c" },
                { "he", "a0b9cad7aa00f3e49caa0ddaded56ed5a20d805580860f831ff2ca2b9ace260bb593418fea9d5f0010d4b5a71b16996268279742853fc636014fd3bddcfec7ce" },
                { "hi-IN", "ebbd90e039f5b0a1d5a7f154bba1062b67bc9791a2edf291ca27270baa22fe77555db432d237f5d5b3dedeb85102c07fecea61a135ac32d2b8dc35d43583e626" },
                { "hr", "2acdfca5661ed2ec00b4a40a334ecd6b980ea8b06b280eb4e9fa0bc097424ec9cdbdb86c83678614d94c5578a928cd9e3ff75ee934552ccc4d92d54249807d2e" },
                { "hsb", "480ce1fdb804914b9770b74759ec26a7bc43941a3d9ca15355dfbbd110090aec028ede1dcfc361459aefa2896a6c583f62e6f372060a6d8e9ad383b888b43717" },
                { "hu", "a3ee01aa9226555aee9b8d080d7110ade357e7212e4f7da1b858dab766fb107bed8bfc8248a7206595b80b5a4baa1c70f388bae89715979d465416b06fd4060a" },
                { "hy-AM", "c9e55768a683e50deb1d743bb606db5d4c8311853647a3a7dd8a21faf5548604e9fee0042d4610e35068dafc666367db6c532c4a663ed2c244b04a0a7091e384" },
                { "ia", "8b412cdc623a7efd986b761e7e89537dc70b5ada66dc4d42c01e55e461b2d0e24ea6eb0bcf6f62f10c218aaf92be015eae6845ed52c5d19143a19c057bd88ee2" },
                { "id", "bb3661dba5fcd4d50167e5aed65b759104dab087946d4ab6ad4383afca04a2fc7d4a073fbd2c21a7572f35ef2150b91f184e04889a62e5e71d89121f4b7e203e" },
                { "is", "f69373d6b68ff6bc3140e86fc509e02fad34a83c3273e901d9df5283f42a28abef951eea42952cfa5ee53b6cd05c1e171195408af7bc507da6ae24b49afaed4d" },
                { "it", "667c06a23e027f5c320e6610d12a9ef884f6149e131c44ee546b695ae1181c1c00573f460c9e39dc3d60042be39ad7ac25f2decc4de893f7516ef27c511e06e7" },
                { "ja", "91e67d6011af6f69bddb1a47c1224511309a003f5e10b39fbd043615fa6f52a77c6ecca9785e05ff289c4351bcbd51b17af3cfd1c4574775170aaf66ca56b4f8" },
                { "ka", "f317bab5d2547b7f9a951a42782234ecc0bff2603267be5716bbde7b27be38d5df661872cc1ebfd629c28b932b2a521b2be26dd73ae6a3732e2608e2fcc0c6cb" },
                { "kab", "e9f08cd3d66fa09c301121e92a0b00488182c706a3b3aca7a111f532e91f8b96e04ab49cb91f822dfce83a235787d776b9e376698b4e9873a458014336d56161" },
                { "kk", "f31d1ca737d79817d9ea855af3decf3565db86487ab8a59ffeebb8f6f2d22236359e9f11a1f3b723eeb9254417c4b4e2a4956567e8f7a2ec841aa93c6443ac1f" },
                { "km", "0afb7fad5f0dc1b84e364c0b88a975de58b6b0a720294dda9029138406738e883de62bb988cb16be53ade4720f4be08184da3da4a3acb440822f5b3f4797d798" },
                { "kn", "59f230f14b3df0b160a0be43edae1c34926e6fd1c64985c06da0b09566ea0040bc20213c6d3190a76f064691b097ed601cc079a3039e24046c8c7b8fbef63276" },
                { "ko", "77742ded22858aafece1d1b677a5b6fd23670365441db7d00181fbcd9d702df82869e3146bf32d56a9df091546eac4be8e502523743539180e7d4744aed42f28" },
                { "lij", "8620366556166e83554160e51c000459569ad51d18719f0afe7f00c98030067b38a32a0d58e28fbac8fe73ea8fc673f27e3fa60cd8bbf91dda846366e4410490" },
                { "lt", "290a07c74565fbb762b414a8fafb8c3dc3f66180cb79c19b47a4f839b856f925ed472258e6358feba890f9e55bd4c671be0e6b3536be8d5784eaa10a7787229d" },
                { "lv", "1821f6f5ab59fbe137f62977a35c1cc89a7ec0ca1686bd470605bf627dd5279a55d9369280f90435325bcab9267b7c5dbfd443d210103eae7f9f1429fe1f0434" },
                { "mk", "f8991a13f8e6cb2c4232d3b542b728fff1c6990895542cc397cbe2e8246c46cdcce7d3ffa122266f5534be01a60f732d05142595068f57b948b66bf6f47ed87c" },
                { "mr", "7fb86eaaedd28b88f97d2d9b004677baa536b54c58ecfafa2cf490597ce6b82f8d6c63a5c2fb019a5288f7504dc88d3aa37e71b4fa52be6bbeb1ed99088f68f1" },
                { "ms", "d66b012e8a8bb02be694004f2e4f6c66b998a68aa98ea4e8628833c2ee544a51b6719a092cbc3d0691b414a3f3d922d799c0fe73f27620d58c4be48e98467d21" },
                { "my", "32567cf3710d8fc6a9f07f13b57f7875b42ac67978b19fefead7816da303b6554c1ae89f9e5359bf745937cf14ef9dc16ca7bc1d409b9895fa42a05a478003c7" },
                { "nb-NO", "cf22b4c342bbea67ad174fda9433af3b910f21613d8bdc817d481610fbd955102ea32a20dcbd0eefe1801650ead107a6b3fe5c480a865f2825cdc85992a1a450" },
                { "ne-NP", "4e10ab0830d6f9a5f04381acc53a6b71f00e4ce87375e9fca59aafbe5d4cf3196a8821cac1346a880d2941ec6d39b5aec309d24c9b9d2b0f46ab12623b2cdba0" },
                { "nl", "d7a76644790f926453c13df651181dceb1f1816f7bef90cd826f26634da7248ed125cd387c062e8432403e39fe3b25c30318f43e1aace23651bdadd1693f76f3" },
                { "nn-NO", "39c31ead83f366a6c0a2c9581178cd4ca441e43dd1c13916daf4b6feddfc4ead74f8be4f1be65ae2b50fef9ee07b5dd303892c3e53baddf07743a448a12fa77e" },
                { "oc", "7defc1225560718081314d15ec13d4c83d9ce1e80861ab0a9325aca9be8e5b4fec89573c03dc7ca80e583ae948cc31c37e2368580e488dfc76b407aa52cc403a" },
                { "pa-IN", "2f5fdd695b19bc7ecbbaeef635e274101f8d17e3f46aa1c8de2f46deb44c54ba8b65b931ca69cee6ae7aa938b0403181d2a1e5f899f6e571c96667845defbe99" },
                { "pl", "0ef168d5bcafc7057652d3719ac1d73f4d23e80c50f005af95fb69ee56de5f5d9e8fa1209aebefed76dd7d2f346c522c9a0684d8f3ecdcd0fd1eddd98f93d818" },
                { "pt-BR", "e234a6db3f467ee6a529805d0f5d83d69914fb968ecc58687e4550cc9f1592df9e5a09a7809dacb20718bf20fe73998d92bc6dd434f2d74140484b6aaccf18fe" },
                { "pt-PT", "68c724dff28395ca55b24a62d611e6b07643a75cf507b4ddbfb662484ef5e2dcc6c54148eb16ca7da646eec58232099fa237b2988ce9a34a78461ed36603d36f" },
                { "rm", "9f953ffffba00ad50f3041bd18388de578bcf3d3ccf1eb49830354d5b2f2e0e2405a28c9ded8bd41b1bcf0680b5de799ef291176f873f3ffb22a5e9c1b39dca5" },
                { "ro", "7126bfe8524f49cbd87914cb3c695b08b7358a994bc920b8eef2c75c59236c12531c7a55fcdb5581991e8250634f817c87906de2d74ac93bbd04dfb6b8f84ef9" },
                { "ru", "9163be957e3c5e0730e734af2d7e229cf2a54f856c47aa16b6f958f5ef2408183c23ee8f0fe5a2739adb38e07cf6b35e131209e27bf6b68357eb3298704bd7b7" },
                { "sco", "090258ffaf8f8d24f3f0505cc0184228bd2b5ae304a4138569b5fede4c6df5a75806925681be814597f844151803eb22ab07df6f6bd700caf79d78b2dc21c52b" },
                { "si", "5830654f5c20ba5fa71605bd04cb3abc08c61e4135d674f11efa113136374e234c6a54ee840f686354dde238821dec9cc99f30ed9e08767059ee2ac707ae0921" },
                { "sk", "352ff98879ac3daa4555b0257353349c609cb83bfcfba1ae1c4d0739149d1ce70755d605230578e54c3dec8a52befc80ae58aa6dd867f06260c446629c8a0704" },
                { "sl", "d34d06809f0b88d151cb618593da8944aff4064014871457ce8cb35171757f944f0ce7f8465764767872a6b758c5401600b263c0ca9da9dce5c279357e14146a" },
                { "son", "3b6cfc9d0d7dd9da4b8808f31a4c75b84b207e04cd4f4703a5cda09f7c9fbeb8d951fda64c71170528a6047e5059e92ea8bfa0a15262f0d5c79c13d5c5d63a29" },
                { "sq", "72371bc3285a5643b2f7537d1dcf4582b4e9138e66905f5e5085c0d83bee1b0dcf9cab833e30ed21c5c1f177d6eab8f92ab857c1c7055aa4cdb63c2369a8d680" },
                { "sr", "8c7e583bb532a4a23dde5fb55d9d079b8bafb42ae128b3c8f8ce58db60e204c28ba2427a5cb74232a23987e3ebb520ba8fb4ba7c546e51e73e9c1df8ab99aa9c" },
                { "sv-SE", "283a4934bd99286bbf4ea63691fe7039a1297fbdefdf0bd66d9655fa3b9a97364320c7e411857958f7526b73c2ae42e6f911d76ed7ee06dff99b0dfee79d2d86" },
                { "szl", "f08541f7767a42c5b8dcd97d977594a532bf27e5462bccf770c8d9878a10ffe9500f153a9dc39ea1061e541c422a9c3a49614ec9e92763d272e1e57bd8b70d03" },
                { "ta", "43c51d7e3454cd828a1bb8ce020d87bd5f0b7a75ad56ec3798a86935854e1055103e1838ca7cc18ef3dbd0ecb6720beba0d7786967b109d2a3ff1b8b364a36df" },
                { "te", "90fa4b0429865cf05a718db72c184ed7b1b4aebe5d4706fa1fd2bb6972187596e7d18acdbdfbabc70bce757837b9a3834ed442aecd5a758f521ef9cf04d30169" },
                { "th", "6b3a25196f519729499f0c8e0bf7015f27f96f12beb7c9143c4f6d48d6dcb0679f430eca65b405539be9e9b5b5f6a450ce4566e5a9cad33822456f015cd757fc" },
                { "tl", "4637f094439482b3b099123d0f0c51abc585652cc3515f88cff87cc74913b1ef4b4b30da40105b9a4acb8577d69579363f18bf5c7cbe8ca8b1d8619920fae2c3" },
                { "tr", "e4a8b11de30a342ba0d764d0d8257f3ff0a6915aa7dd2f817aafd9d6fb34937ff3fffbc2a139de851e85cc3b0b28883c6344e737065a9633f52ebabec1769502" },
                { "trs", "1dd891c592763d885b634095be82d825291c75e6a0986d79013931b76db5e3323f5c006e13d0c3c6f38a4dfb8b5b7558f9ddb5f7ca4140340a8019aa9fa23f12" },
                { "uk", "034c7725335989d6c97101523757fc03ab6a476388257c4fe53b670ac802f60b0022f9968564d126af3773c884960f6a99b8c321a49627d9801eb64ffa70b6a3" },
                { "ur", "e3a79263b729fea32f3d4c443f9032739c543e6869bb0e8a65cd75d5c990c7852cbfb23c37a6083226286ada9a618ee6585db2645d3677246f47a50890cfb9b4" },
                { "uz", "9d63dff8792e49f47e7c5309cc35e8d0dee66da6e9e942f590705b2e6577462fefe4ba13a44d07a8aee9903de2eb6e580c0eb3438798f03ab1b6687813c7e199" },
                { "vi", "c079f58b66e3310f043262bdca7ef8514bddc7d0aaee59f971b3dc3a8a2050b8f4b16bcc52a49140517a357c110051f7314c730116c6bc3bd832d4ddf218030e" },
                { "xh", "70257f68c08cc71c098d5918875ac820ea07c37990e70eba2161156835bf781c3f2145dcd27f3e00f7317523c21a2463f8cfd63e08fbbff374889159d48ab6c7" },
                { "zh-CN", "e3390f233ab8b6614ea4ecdd909f59b1668e08f9b3b08e092628507283747494d895ffe45d421b63d39e245bd35e9a6a0a037decf0884bd3128bf335d70e2a8c" },
                { "zh-TW", "78bab15412b47e7546dac3e974907216d8f322dc4551fd0081ad1fd647ce783b95385566bd0fd0bbebc94a661ca70fab323833c77303e5274c057513a4368180" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.7.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "0681f8621c92f5ab2b2ae3f3787d2686b6de3e9dec45b42f4ce74300a110dbfeb7701fd119206f71dba0d952732a03fbe4e4f9723646169dd9be76be8eb5b8a6" },
                { "af", "065278fa0a0c2fd633a8653280123a892610eeb689835ebe129ac9c80053cd3a7c890af8593754e1b470a4ee194596fb16cb2834f3af24b41cac1a4912fcf435" },
                { "an", "0ea75faccade6327504906f4ff03adff5e9aa8e4fd093ce0269caedefbf207e25ec0b32c5ff1478f959586b817ffe9d9cadd043796ea45b8cf39de0f8ac25116" },
                { "ar", "a2e900375819575e0475f310f9c96ccfef655d8b0ee048ee1f926043945ae13215a927dde0f7ee201f0be10f3937508308b1ca5d404ade1574ab9157f0b02383" },
                { "ast", "7da0ee32362ea3568e8321adafe254613a4cf925b872555dc53703bb3481c0428be4b1b8e79a43cddc54d0da15d4782e5fb6c7c6ec3542d5a63a459ce6901923" },
                { "az", "966a13d387e95cb7054cf1112309e5f95e7b2d70ff8eae0ff65ccc77e5690d8b8a2823f13a494f4b38866ce37befd7bca0734c375178b555203c55d9a08057ee" },
                { "be", "2ac63d9632f7e3986c68a963d54e7f0ed010cf8ab537e113b9728fe48326950688c68959411fc30be2d325af4db516af38b4ff0975273afd502a773b222b481c" },
                { "bg", "a715f598fac2dca7e9c225d664a519e54adc9000fc81245e482636fd3163ea6e31d832d94435385f19b7efd7f08fe0f92f6413f6c26de99e8450b51e33797129" },
                { "bn", "803563c80fccf26f55014d32187ff07ea98652c789c2907ff0e7b4b841937aaf1a5c3e5ca37399e59a3dfc5e5552925f43643ea5a07819b29bba71b5c24cac9b" },
                { "br", "55f4a0852a393cc9f2b5ddc7fb351fe817293c39c109f03566cb970876023c44b2360a9a3e0ad09c30427d19797352066811d37f1f52129b331bf922e989ab99" },
                { "bs", "f1d3664386cb048182080146ca42b5b88d7a6da6e65b5339a5112b7b50b705d4edbe0ec9a87c1cb59bb93b7c3f7f183bf0af480714d4450119899290477f1f5c" },
                { "ca", "09235e8be7c0d92a8a5ad63f7bc419e895b4d8c81ec4d0df214855b4bd163cf0a542322ded171728ac7c447fdfee9b71a8edc91bf23fbab8397043d8e85b564b" },
                { "cak", "048dfb5f149ff478c2699b8d58196b68a51de5a011a2d2a6f25d73c563b937297b22e47510bd8b97f451f91604258453df7589e048d07205f2dc1ee1ac37d507" },
                { "cs", "7d92ded9d1cc5868b5fff8787203aaf0f40cbfad67a12a96646e3fa59d5aba7d91b553a36106bab5ef41dba55a88caafc6aac413dfa91634c25ef9325d23cfa4" },
                { "cy", "a5e4d42b03ad63d0e18f77b5963eb1cbafbf8d1746c0524b499b1eeb4585bfc53f84d4112f14b304679a6a7ecc0b0dfed4d3596b449c186cc97adac9d60b625a" },
                { "da", "28d50c41fa29f2b32aa121c711312de49f0ac8beec57a23dd576108e8b2c0d2139053caa99b3782c748364c67e16de6861878dd17e1440d6de5b2d39a78d28b4" },
                { "de", "2b15b5438d39cfd348c319dc2319ed10258982e7583fec5951bbe791bbc4ec807d409e41ed9be2b8864dfbf34c3e50089ac572e0cc80c32e52b18970a1e7ce7e" },
                { "dsb", "3b74069e6498b639d7d0cb30189b7e37fd13886084c683d6fecb47809ff36f7365b66f531b97a81bf4743e4714a48b212dcd3d3d1ff4f4bf60e3211df67fa0de" },
                { "el", "1b551aaa61d35cd901c9724338279a2eaefcbcf33186b7855e963c04a9ce77069bdcff8c3d311e0c6e4d83f3beff3298d74d2f46a3d3c3e367edfb82082a40bc" },
                { "en-CA", "a7360278d9f294bb1abdd98401d3a688eae19c212aea67137ff2282393dbf07217f795d7e5de5d3fc951a3ae4cb2f313d3d84697d5d19ba8593d4ff52a32b222" },
                { "en-GB", "49c9890fa4fde4f39bd4f1e917295d05e52694e668b13d457734cd9df6682b7a3d7a98524b4f29cba81ba0c3f889c15cf240e59a6bdcf534c79eeeb3f0192929" },
                { "en-US", "6508d7854ee9e8bbfe15955137dc5a9855a814933c532855c3105d63b6ac4563d2d1310c2012d4542fa1b6966164a55fb667734839cff365b53deb3cb3f60efd" },
                { "eo", "70be4073024b6fbdec9a63ba6a8139b9ecd8744653ee0c9c965c92190e42a0fccdfb358ae2213199bb92b081cebd5cf48222413ae5b59796f10dc5a5795d1394" },
                { "es-AR", "b23284a90befd4b5aaf2cb12e6949f28b85c581a97d49a2a94c9728315c19ae06012e9ffe3812ec3e606a7d9d139ee3279eff0e82f9ff786d1e4a6789aba8d9e" },
                { "es-CL", "05a5d3cf45b7aada412329df6d35571ff72e2d25cdd2385a6c88727d7c257e2dd9201b6fdb21a8ac2ad7146efc1e7486d18587a9b5596f3abc9f3c0da3184ed0" },
                { "es-ES", "50b4081361c77954a54438639081c09e1273723d5881e1faa1b9df25f702dd6854f659eb4cb31c4067e5338e43e523c1a8dd807607354281c577104b28c9a933" },
                { "es-MX", "33b0b85e72eca316fa441479a721c01a06e005eb85ec0f3748d1d380adab7760d01c39a2b1fd87cb474bae9e03b7a1fb12fcd3a3314ea82e27fce415b8a40f6f" },
                { "et", "ef45e0203e6e4a1da9a33ed78605a2ff15a6287a410a1050b7a46510c83823cfc987d018f3ec2666a0d1573ea5d8567ac874e9711a00af31828036c02d9c06e2" },
                { "eu", "749dcb945fc2e36f5c773e02a5efa4557cd430eca8f854e99dda73e0e1629af74a0ec69cb698656465d09585d9fa59da2ea63a89dcbc7e6f33b8c26dd61667c8" },
                { "fa", "b59a0ad60215afb326b8a672ec8caf1f3fcb1740a54cc8d225a0f9dacd6a46f8ed6349181ac4c6c84fc8fe99472ae86009812f36e97bf1cee013cfb0ffd88a62" },
                { "ff", "a27d9725041817a2dbef4761572bcb1c8f005047e20517de938adf63905bf249d642da58da2824311b5621c51fbef8a777eb4b9cbeb4060522e679b224d5cbf6" },
                { "fi", "3267a485ba6ed5511bb9baea33711ad65913d0d94fc08c711107d28461f0f49000f11769b90f7867dbf75d8ad11fa81f17f782601cf05b531915f6b02c9bb326" },
                { "fr", "6796da29441e0783e3a586f6ac1f9cbb9d2df1a4e9db4a5ec02ddc646c41b47f1b5efdbcfc2e62ce02156aec600a4084acb8b87e0bc20bd74003529b823d169a" },
                { "fy-NL", "1f0e11770fafc03df969fdc6b0a474a6ca3c22287148cd154f6d47c5b6c527bbadac832a2fed896b2c53adbf3625e199feeb9b737028abcbcfaa10ad049f6b49" },
                { "ga-IE", "5521addc2ef4407df1dadfd914768d8e42723c5b5c416fbea10264546e89300a17d7bb26cc6da699b54978f7e86a37fddee35e0c97d5af29cd3c9ee59e080ffe" },
                { "gd", "f6b684080acbef583fd30fa97a7c9b84c98b395e4a56be84d7ecd9eb13acfeca365912014d0093f8ee65fe211f6e9ab15f69d82c258919af0a15ede2bd394e8a" },
                { "gl", "1bacd7a1b0e75b295568e4e52ca38280bab90934f8330ae1392efec782887c5c4431192e5c25b437a29b7f0f3617d1dad43717f25a047e3d15f0429df5a25c28" },
                { "gn", "1df6b3301420668fd0ddb0a489c2f3881ea03a95f59e1795a050dc07d4d90e533dfb6b9b9470c5ea3bfa881d94f537eed1cb8755444c3af577578c956e440616" },
                { "gu-IN", "f7b598a339508713f7cb6eaf257eaafcfbb101e023c1e9ea0082d81cdd4b6b6e32752307f93d76f9e15f15bec7576565ad63a560bcd256d5a0aa724b394dbf73" },
                { "he", "785b33f021f7beef5658bd5b2c5664bc9e4638b67b25f7c77def618c4a2b84846e6aa791ec242c7b99a1977a0f09df501ce1c433104b01311b2187b4703085d3" },
                { "hi-IN", "69ddaa466aaf2620ca1ac797874700f6eadf07a751979ec1a040a7635be4570e61b3691b8b6b8aa6b35835ce9d476894b331d3ce49afa7ddd518ae504a654464" },
                { "hr", "c087853e4cba1b7ed4c70d2aed8824c4dc0704d87c82dcaf2542e6aef72524365c8d8dd1d237217cf601912d5a5d577c5e3524caf9b260f705b17e1487fdebdf" },
                { "hsb", "1b58ed4d27f1894b5112367f808feb66881dc595976bdb8233b50898cb8cbd5c8b574c0876a185c5638e2f70bc906b5d193b8241b316f85e51fc1defc0c87b44" },
                { "hu", "8aea4481e2d9f02fd4dee121c3c7f639bce0b637206155d3c62eaa503902d67f12f8b940a32073e1bcd887eddedf97cdbe10f45c0a38a2d7e6eef3e6d4f82aec" },
                { "hy-AM", "a805a62505b3a69b0d47e82994a293a0468112cdc6b1ebdab10767d91113f9c454d0902861edb385b813f45003011c10fa53b491ec27e95afe6a7a4276e42ecd" },
                { "ia", "336909c787166b290a6335b50082adc2d0e2f1daa3f3aa303b9740aadee2c63584b068b5abc40350a03fb4e49e9ad80478c9fb4dd15a366e8bd24addbff2381d" },
                { "id", "1196cf86a64958ffbe11bec8bdf697b847c9fc0fc31863ecf10f37ff0d897c06c188246eb4083cbb8d69cb2087ac0bb4a57c5fecb446b2f9392afc2d6e727575" },
                { "is", "e4a0c3bc7112749424a01c6783c509afbcda09c436a56dcf70554e136508487719a3429079ab7aed07978dd2671f24ac2d22fd7a85f1e146b72fd9999a6f1c99" },
                { "it", "c27335361cd1a8d8a0f8bbd1d16af497afa292262c8946382a0610c1965d5aa5adf660d5fdbfcf4d33c64dc6ec86ddc5101d88e8dfebb352c957e9f8bceda805" },
                { "ja", "0a07f6382ee7fb537750a9eba85661525687add223ef77e7623cc5469421a966c346bb599a7b5181a969b2615c017f1cf5817dabce89b6c0a607a054b13974bd" },
                { "ka", "b4ad326ca2f13117ddded00d79b7f93f551809c77106e67f45881fbd3101d26e796344a50dd3760a08e9beb8751b0550524e826aa6629f7f83a5f65bd7181cca" },
                { "kab", "6e8b8edfb2d786eb7b429378092ad485a2c88b1620e0e7ba0e9f6e0bed3908620612c8b0d1f24517a4f486bbced86bfc44766cd3ced209f290a286e4f403248c" },
                { "kk", "1b29f7fef026fd725febabe0af9de31de427d50c71d02e9b27649f51cc754b98b348e017411c9dc42fee892aa088ff091ebc647608cb60cefa85df0dad1688ed" },
                { "km", "e024657877cf35c4cce66ac794c098d89c734ba0c92f4fde81be595f087b9bdc359875aa3c5ef9854ad350be9551417c0ebaa3982d60253b07457535d3928fcd" },
                { "kn", "27aac68be94bbeb89b58577f5e70d58f13a6e99bfdc66197f6ce59da8ca81821e074f1a4dcded6a9bd362210dca80c7be31b6a252262ed77ba15d7f1f18902c4" },
                { "ko", "5f2a78e880df4a04cba75a5656317aff49a72d5d9909107ae093806bdd83bca43c1d78d78b4a09b0ec43afcd0e275d9652677351e6b35b4f470f27346f17f442" },
                { "lij", "bcbb3b1704b38b8b9050f81f4e2e874ddf399060b0f238e2c3c3b91f8d5f2c4601538a99a6a1f2ace53f9923177debf9a2d9b9b007ba7d8aaccbffef333890b9" },
                { "lt", "67b8b935a185e9efacc3f43d4a90506a4aa1e9ad688e4a90ee802fe1eec19ca269e1790cff7cea90825919d88c1d0dde332346be8ad0e71b326f582b3094bd8c" },
                { "lv", "c48326433d41aa3ff8225facd310f915bbb09060613d4fb3267de0ece071125182f365d2a618a08083d4e21e7b37a80c96b73102ce965f880c1c3d893f1cdfe0" },
                { "mk", "247c3b9fad3702358509c98e0f7915c493b4e8dd69e944ed94cbcce8f13b9610370ec978449878f810ed6a4e521b1a13b1231e896c7c5721358689165683449f" },
                { "mr", "dc836204169b15c9c7a6b7459bba45d42e82e81d129b1ecc7a65ed5a359741ded3999ee33078b97fa20dd4ceff20f26eb5c8c40df41e733afdf4305492d46b17" },
                { "ms", "86c2ff809bd3c231f0a61279b63b00003ab731a1b44f6c6f846d7e056e03fa3aac649e30d60a085a8267207820d5e6ec10e90b71372138e75cdd7cac61c7a8cf" },
                { "my", "cef455e7782a5364c3aa999ca24265d4d1afd211cd9352aeb47c59fe7bb0ad4c1956f9498dfa7c9233f86b9aef72a5f0342f590f40a70402d65e758072d25edc" },
                { "nb-NO", "322086075f9c898c6fa751fef50a6680b4b9ab019f3d9fec7d1f4ae7dae5b277f6e7e415cc36d71798b5d8747b217f74c73eb8e0b1b2fdb54534d3069d68f5bc" },
                { "ne-NP", "941c7ec020f808394ca430ce12a246e3f492076653ffe708ae2f015eae65fbdf9ab1e8caab29d4561f285a3a40a726637871af6acd8d681860ec782111f2e13e" },
                { "nl", "649c3a5dd6ab2c0b4b1eb0f3518b09ac683ae5ebcc637b3dc60270d5435308494f617525f6f072978c5f16a54243767198e7d880c34418d7b541c35a9d90a993" },
                { "nn-NO", "18e7d63bbd98b497574bce3ffc68217c5f0adeca2cb0991c0cd5362c64674a830050c3773926ee39344e99969dfe80fdf0805b2adbada82be95eba78e6096f53" },
                { "oc", "577833396be61c310c9d27e78b672398879a661cbae6110087ce183917167d5634fc8b7dcfdef2d1d6360c989591e98f499e25c19bcc85d934bc69943a35551d" },
                { "pa-IN", "76d270cfc404eb4886901ea069ede9402cb0c3cce6223cc18018cf0a314ea7cb38ad5f7c43fc246b34de8825bc25c6b49cde0f6024c071983771c7c8de9e4123" },
                { "pl", "5a481da90df8f94de7855f6313c128e5bdaf82ed7c540546e2d457ecdced6f26e61b578f786e8fac3abfd9b8ef5f1b5db5f0e6a7f88c04a70b2ddb208f808297" },
                { "pt-BR", "8dc012684e7b94a5cc27572745b040ce1dc003f0abc5024aebaa19d15378e3e38e6a3404aff9ae96811efa45d39827b73e9a8c8f84a9f8986807d6db86055706" },
                { "pt-PT", "f2bbac0cd026874bb78d8e8a8ebd252fc4cfadc112ae17f5c3340c78e88523166eda6a07cf060dfec2c4bf05858945987eeed5badd6f5c31c0b5b8fbb530e075" },
                { "rm", "b57c66d7112c7832456ee4a70d30e24bb45f9372789a14ebf5a66e88edc8441ce94e6e021addfbef6b2604adbd75037b09e70fcb4bcc2e62cb845dff581363c9" },
                { "ro", "b00ba445bd8ac72929d2953e4d12ddd62c08fa3e7ad9cb2082ff81ed207ef85a230ec187684cd7f15f96cda2d85a25c498f2204cf76f0af15e7296eb88e29aa5" },
                { "ru", "cbe766c2ea5530f205745218cb2a1c1e4525993da837cbedfb27b01c47cb312737efc4bf78eaf47397be6f4cfe4d73ea41172b7b4955b7d5f8d68a870e80e0d2" },
                { "sco", "f165795f9a7222bdb364148d127796c1abfbbdd69f3018b707c6ba691efb8257ce8bba002559a574ca48b48072bff29044c03a24e39496652bcd84610438fc18" },
                { "si", "75005bc3bbafc5491fd9974bed268c80591dceabdec9a2fdea786e4ef1ad16dcfffd5a232daa456703cea75715210e6d8c865b8905ec9329d24a7e4dd229b0c3" },
                { "sk", "5984c382b31c092c8c8348cc586fd731469ad5d5f63b5533df41d5fac5aca58a7431a2ad11a6efa93ef30ad068f3a1b5192cb7b3b9ab642072b2f6a984e3520a" },
                { "sl", "ecf781584eb3e99e436b5eb6bf4f81b3110f83623f890818bf1da48fdf5e8a1557901fbaa01e9e264cc4870448b69915134e370e9bf1865d3ec25b385ad62fe3" },
                { "son", "f3577b4fe04a1a129ed89c4059ec355f0e030cf683fe1ff415abdfc979ddc440d8e51fa571edd64ad5c02ba99bebdefb0757e5cd5f516b1e7a6d9bd7b5c18a87" },
                { "sq", "0bdc6064aea10f72cdfe95d5be034d2a18716c9f4c36c7ccbdec8962d3642733d0ca5f6dc72a13c2f7ea77d993d1ec7e9fb6391f129186cc2ddf78e8294a1857" },
                { "sr", "657ef349543aaa68e5aa7aecd66bda8b22d05a1fad2956b523f8e23ef769e2151a72bb11d1b88b378aadcd05604545bfbe7b6a8f34f7408e4531573f870de306" },
                { "sv-SE", "46bbee0a7b0b27de1efb019cc2edbe514cc5837008c7ec1f7891c125b48235d663e021e8dc82db9a9981c0d7f190ca35ea31643afa5770db6c87e1d597912a1c" },
                { "szl", "6b4c9c92a1f86c70cff3832671a98e37f37a9c20d1fb9294beec08c270fa5905922d29bcf6c55843285b2ca21ebd919b93f926a8ab43a4d02828529fd0683431" },
                { "ta", "13a12b4aca7fcb5beb13633c0d0febd768a02591b3b25cf0755f5308ccab9e8acb028b25c7b08547a772b8664a8ac5b1d54e52cc8630e81851246156758c4039" },
                { "te", "a018436705efb0eae0cd4ac1b3c96d1fd5e131aafa102da582077a9b0d42999596a5b99c681c23049400f37e90a30b2e61676a0fd1006cdac9c56ae3139fc778" },
                { "th", "7a664924092f8fd8c6864e34d82ba24162ea9c7576103680fa45330e851f06936a43fd61a3e21aabc6434f011fde3740eda0a18dbdd3bfdd76438f7e5a1c30c5" },
                { "tl", "c34ad9a7ec1c9df3f59a196b38eb75bd0a1d36e5ab04d4262fa483f12063f7759e55f9cba8b1b259a35c698c04d55e77281335ebec01df1a4fe8453bbb41bd62" },
                { "tr", "ce1fd9560a1a6109321300e1dedf064a4813657f2e2e2979340a2f56aa2c8d73dd8fb08dbbf72174eb660d06f4352f26eadb9e6001f4f2098062c5766488cf77" },
                { "trs", "2dbace998c658f005c205220ce7b6da85959b98c770c7571e59a3ed5ba0ad6b6425b662e2f1a687f95a01161d04972e5e034ce0cbaae3d877f8707235bf5b667" },
                { "uk", "b10ddccf6a9847633809bb54b83035be12c9424ea8f522a5effdcfbd1e07371ce431dddcb3c12eb02550b0295c761056f5e436c899fdd27f5c1b8bd5f6a36ba4" },
                { "ur", "19e184b3e78b7d7bb6db3a680573db2cc569edc58a7a3063d4921dfbe0bba493b628dc649948193dfd3dfd0b1daa9fd68e354af91ad92d3289deff5d63ffc870" },
                { "uz", "e06e1cbef989c28c36af4818fa8e7366406f9d508bf75ed4e2d3f267b25ee863858dcecdb89953b05e79230717244c85f4f8272ab8fa80ccb58b8bf5796b473c" },
                { "vi", "0d2ffd387544b97f1a42d04e97d0dcf22d3d96585055571690d3050a1a71d7831e130aad9950f9db83fb429c9caa9767f8b0cc8e576927a43439f4584d5aed58" },
                { "xh", "2e77be1b3a7dcb0289ff835f7c317084180cc265856dd28625e3f7f1c0f46b4bc4aaab983156c828c72834b692fc839c4880a27af5c4ba7c8a75a38424bbc714" },
                { "zh-CN", "4ef25acde5a5f0021c42a0fdc5cd90a976a68ebc21d36e88f85106fbd58fa759e14a02f6cd6f2d8ca368755bd752e5d6eb291b2cf0a9212e632111df5110bcc0" },
                { "zh-TW", "f12da8e9ffabadaa72cc81373fe50c1425ffa3d73ff89e8e91d11c08e2b0b712090a1de0bf9ce8b326a340f91f4817ee7c7df6d44a446c1732ad4bdb363c0ab4" }
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
            const string knownVersion = "102.7.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
                client = null;
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
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
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
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
