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
        private const string currentVersion = "122.0b3";

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
            // https://ftp.mozilla.org/pub/devedition/releases/122.0b3/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "58872bf7717882ff005a27be81385d7d947370c3589b8b169f50e18263a805b1f31c84a628fa71ba3203bbc03cdc48fa9a959a1a544f46ce54d6d16697462a47" },
                { "af", "e023a4819138300f6246f5558b7e43ef6608f3549524c652e2ad44d72411ae8e60a41a4d0f9cdf1c1ab7884344df49aaebaded9e5c3645ddd4006d66a71d7dba" },
                { "an", "b710bf69be56ee99ab3d1ff90159773a6ecfe1e8637cc445beb2f2e2960620d96d25c979adf6c9216d5fac0c1f39845290258b86dbe5dbec1aafabe1ae4580cb" },
                { "ar", "1c5953a646069ae1615528b7ba2bb7e140f697c16b389c53dd46a3629d0aa1949ef7b38d2a49dd0ce9bdffd54dd9c5465b878a533d492c292035ee1aefb1c546" },
                { "ast", "a488cf742365829fc1882965c62caaabf28c38c3a66770acb1373f6cee3938d0a51dd9f821b2af06685730be916c7408114b784bc0baf1dc438e17e991145fd8" },
                { "az", "66820c9fe082d823ab37e1e6088664a75126edd99d9c605becf572b2100c0a3ec0a13ae89157aec2c62bc3a3f40b63146415d5e13300707542fa561f7581d480" },
                { "be", "436af47e3b58a7f91fc62b53dffcc6bd6ff50e86f3023dd375f34c33919fd79a238d237a38a52f5c390a301e89b6d5e82bb715b329d148d3f31b6f4397bc812e" },
                { "bg", "174ccbdbe2c1b5c91c0d0d0336454d438f66a7a1263dde19d37fef8ad9d026067ae95a5fc66f9e7a1a216f3bbcaf0d04f1bdeede56f28a36aebc4e2c146b2f0a" },
                { "bn", "132cb7e1919dd308598d226a403c2098e0552821fce2daae2fe0ee666135f2c2f709cdca2a5deef110c71155549f051f8f3c2abd9888301af85c2b67c1926042" },
                { "br", "b763a9959dbaa496fa32bdb7a73280af7687ae284fa1d08bd9f5d15b09327a976bba7fbed0f42c695d7555b3765ee3772563d48f4762fb0f72e2dba4d823f9ed" },
                { "bs", "3a0409ee7700f986bd02237d7eff8e8384aa013a736ecb6a8dd84f990664cf1f01849155957d1712924d7e89c9536d5091ac02f42e9cca55b67776385a85b345" },
                { "ca", "750418cb6dbec1d70a93e7352b7435f7f471a69c05b9c77f8abc244048481820077765e6fd9be5670cf28e5d7e11dee30c4f4f1858bd82ec3bb9c6686d9bf61b" },
                { "cak", "1969d7aada5ab835834f8ee22c9bdb3e2a8f59c525da46c90a26aef585eb298a9e316122517169b6df1a91298b674880ab882f31a920b6db36d3ac53c5b4cb05" },
                { "cs", "8d19417159930be437852cf5b7844e897aab775e298c402037523da3786187a0489daefc9a73c32d381339402bc883f1e7b6b2e3599ffbd038806025192641f4" },
                { "cy", "54a2d740263d94e930639c2d3700dc513a8ef6a68dd4d15f70b9564df30ae8c11064389ea1421ea8c621da552e9fe1973842b16b89915fbad49bb9628476bf58" },
                { "da", "7ed68bb8fa5299aa85da21a84542826e38de24caa59a36dc60466241357b82e24f89c8a200033b2d5a5c3c1d9c49cebd803254492f91fdbf8e0989f1b43fc234" },
                { "de", "ab7a10b76be8f5c0747dbafaad19412bab5d8311d23c5272748fc7a85b19157da3dad41dd3a1345afb34fff55b9023bcd5af56c942efc450fada16bff9c2cf43" },
                { "dsb", "86a5526d3a3103cc8049a4f1ef82f167ce8233d25987ce3cb7da0c765d19c88dc700577f557d7fd54101449c313ea6c22eec2f9a061f91231c5d765c710d9d82" },
                { "el", "66832e059e8a3de9cbff9129a52e2011ce0cda41aa17c599aadadda6b2d689add251f180ad068135bfa90cddefdc0f86d2159d0e6494e11a60df4c816a324051" },
                { "en-CA", "0dc4e52d2cbad7c96e361d23fcb44baf18fdc7110af263093586dd0a1e30934b797ddd9d6858c6ef562ea8eff0544f79f6339f54f423071348c9cb0fb9d78f7f" },
                { "en-GB", "477c280b5ecaacf5969892cf354d6e5e54eb9d4da319c0778d0c84a6afd91110e122a559579e9920914b36ab1a0a9c910eaaaca2288a1413110548e204e837de" },
                { "en-US", "0e6cadfd66ffe4924fcc6d3422000674de9d29162cb7d5da513b3f7d668dfa853b44e8595363bb3993b01e360a8d1469175c269f349df7d2a3e2bb73fb63634f" },
                { "eo", "b03c05e881efba5d13509d79578b7e74751560ec2709384d8da795d13812984ff0f8e9c33f17a8538b1adf58e89619dd339eec2ef56cc025003926445b646b11" },
                { "es-AR", "16ff9d26c3d5e3c1b48e645c5c583a0395f6b8464b1628a1332a2df9cf506190bb74e4dfde0bc047aad9945ad0f96cd2c48c53634c11bab81e2d237b4756334d" },
                { "es-CL", "2732039ec9121076e845a769ffb28d4d10fb8dba315052f8c62162d9707ec828fb8a1d25d4bee20d0644ba6672934409c0f7064ee2a6b7c53ea7ca29c8afa65f" },
                { "es-ES", "504d1c9ee565146e017df028cd68c5e5fc144233ef8356ef74c6bd36d815174f2a2787cb04960ae1261c7cbfd93e0f7777f987b7bc0c5b201439c6d00ba2cb7f" },
                { "es-MX", "5e26ff3043b3393db4c2366432680fd2c03fb111695b4fd5bf01702d774a97f22a36ca562a5e9f64f46c2613a9713e163d030fd32d517b43f7e1f6996394a70c" },
                { "et", "e338a6bae7f941c61fc9e0b1e3b85a126c47b05b5fde0b85c7e916308eb44f3b6ee0874a86a1afad2e9a2f53f184b8ac2a193e2b7fad0010a56f7e4a63a50766" },
                { "eu", "ac597d1a21e02c3f366fd5165ba604b15311a54143e42dbe7ebbe43866fe31e74f21ff8f79e1c362fb76763fcaed12547c3dbd84ccf1ca29d228156f55e64722" },
                { "fa", "30c86db98bc5baf3bcd71a8451ae9200c7aaab34a674dde530e651ca26e9300b91a906743152fd5e4ef925e7436114381e7ef5f8949f04849de14f1063e1edde" },
                { "ff", "db8de7c915983cdf2cf2cb744b6a5d7aeb09995150ad81483b9e09f7fc58542f453f1d1e28e5c615681a56de993165934dd16522b198630c856215c9c9947009" },
                { "fi", "8cc09f0426eac54cb75cb73970a415c1b4e28c72d0654d09df1b4ca5d44725f77e0a14cd30f039d0a01503518feeacd2d5a33788a2dee396d5b1fea6a3b97441" },
                { "fr", "9e1b8d8e2567126a74c168bb76132ef1fac44592ca030680c334a0796c2aca0162167b1906f464de6de5167cd8a76fd7ae954dada8f401b7c25f5005129bbcdc" },
                { "fur", "fb9295d76825b5d2aa8a39792eac39643e4844a844992549fd626427de982a9cec5340dfd7a6408af6f2f5b5e62e84e08b77af79750469f26e569ea76fa27526" },
                { "fy-NL", "5c14ab8f0fc4ad3a44c6f4ba20ae3ab024e44ec13d3c3884b050aa33158bcd6fc595e7e571048f5ed04f471f58d38c1c71438a65458f27cfd60746020322aa46" },
                { "ga-IE", "20c91f4696f44678ae535e22f1e975bafb27813f83f29df69d71a603a67a0e8fcdacbba8319f8567cbea1825da613c489bbe9aef316016551b16635c15eebfac" },
                { "gd", "a8550aa6dd4062f47ea36cc1f513dfc88892bf4c3a090e789d87e1d3e3e3a3f1768c0ec62f0ff6c6946891806b33f69b920ab768b199dde7b063080342aa7527" },
                { "gl", "a925a48f040ff383d57489826a6f5ae58ef3c4b87baea70cd3725b9be05c269ce2f60009cd5e88558ea3b0e667e878bd56d0f9fb36d8c331f23d3c731ecaa96c" },
                { "gn", "5168e7e3d7309c7e07013961057e5fe3963e6f3d5b334acb2e06837a71c1c9e695f4ed81cacc1047e588200c18601ddb37bca7a98bbfd8873b14c2e9d57f64dd" },
                { "gu-IN", "68b4924bc80cd024593e0231a02ab4f7b0613a61cabcb0da3e8cedfa33ca729e021c502258b383b9ad3f4f4a675a20ef69bce65caa477ff0dbfc1a3a5069a0ea" },
                { "he", "96011742772be80a059dfa5b8e496195473d1c4ed6539c1127bce9ea61da4ffb62186bb56ff499c304aa7097825cc35220f77322fbc839dfc7bc4de0f2390855" },
                { "hi-IN", "34c1faa04699860bc0c9b24d84a532e2b4bb5dfffa69d72acb0a42dd46d84dd3bd4bbed95cb5b3beaea66adfa1b28df910b59e44876c13b0c80e1169001e7e95" },
                { "hr", "43b6f33f09aeb3fa02998482b579a9e8a6f38624b7aba6f00204add846d2f7dbeefc5e3b3e6b471caece3860d5c2e55b155d7f8815d6b12533e1218b92b88730" },
                { "hsb", "22cf94296ae9709bc03b6c12d975e83ed5d0fd4273e8f15aed2022a3b33d5fecdb2b3f059a584d86ead3ac0eba000d01dd90cb7452c499a774ee8f8380871ade" },
                { "hu", "22f0f59b8e5c92b70c9c32b0ed16ae170cbd47ef16e69a6ede2b2f3ee163457726efabf839dc98749575900763a891dd447b1d4f0cf00a1fccba7373247bf3f6" },
                { "hy-AM", "e7cb9447ddf9f1083cf83aa260d06d00f6acde1d65f4ff52ebf76d153011593f74431b155620b482ff3bf3e7027acd8ed9b4415174bf28f763afe8498e83276b" },
                { "ia", "226be6b1ed4c960c50fbc4a77557ae3fb6bb9d6789fe967090e14c6434331142a4c6621939d397ec0e6012fd70de141638f6034ea7056650df49a976d18725bd" },
                { "id", "7c2108f2e687ae3b45b7fe34727925c519cc272981b4f0f608a4e10834904a49c3f00e6917adda986448b38a579905a0a426211382d11667c3ab00180d5b7aa9" },
                { "is", "a397d04d3d7784cf4269f1c66b0a40002f793e99f4c7aa3ed25b844e4f90e50791d9ee1e856b5a1995f041fdf512efe4259050816173b3f0f330b9254e01eb66" },
                { "it", "cdab28bf7d15dcd13caaf12fe42bc09344fae4720172588e8ade777995e312f2fe79c744dd393aa047fb88959dbb4c300cb06259701d6853fbccd29ee7ef4282" },
                { "ja", "418ea6407d4a1f1471a62fef905e4ab321e966fdeb1106a930a097c55d147a2fbad9e274d0e43ef8a0a5b1c2c1594d4a0a6afe59ccc533faf93dffb7c10a0060" },
                { "ka", "7c02cb2f0862df363296eb5f7c4729d5f1f6c801ea2e94de9f0245938ae5c52a6f0f17d76fee221dd19ed5c1af88e5b455888c3e034950ba2dd6fe605752771c" },
                { "kab", "7c2767d5ca72f63cd7743d2932aa75a7ebf2f294846f9d6fb04dd50b12ece3ea87836fc199b63bdd1a500a5f316f11f81d81fd51317b7f03bc851e1cd7c3d823" },
                { "kk", "7e61bc737f593740e18fa0a219b9feb07352e4c3d667553b3fcfffb1cdd3f73171401bdfcfde642fcf2399dd6dd1ed6b0e4598d4f9ead7999a59d9064db9e0f8" },
                { "km", "f646ecc766658ac918b10958fd55dec64c360c4a1ae18fd6462e487fc9ce34c7f5f73a22be815d0b0b6f076e533cb844fc274e50678e44aa91633fb98c0b96aa" },
                { "kn", "240612db53c0dafd31ec53f3a8e6b93607adf6014127ca5266387d7f8532fad313b8ccdb1077c7c5fac59c7f88aa78f863e9aa4a259078c8800d3b2486e20b2d" },
                { "ko", "0c8f6841d2d625303a5e67ac832c4806911f062a3fff1e954cbcc2e25d360229e88025da6a254b1b1f1372a1a42c3aa2389d40c7d5d2c7fced6d5be9ab5a692e" },
                { "lij", "8b2f7d43525e820b241a9d0231945d2369b349748d50ec5ea129c45eba06913acb3563d9dd25df1a13bbeeac202d0f0369616fd7f7a584422d20fad235755a2c" },
                { "lt", "ca8a5ff5e7a53d77028608391e88cef2b3961741894591dd8121c6ed9363d39f904d3a93f6c73b246144f6e618b10003391b82bf395c0268e922c1b1aaf67e5f" },
                { "lv", "41c7b1a5d1c6b2c71490fdb2e0130279d516971caef1a99bb80048c9bef4b91303acf7fc08fe244d25e0628431bfcde918223a69de5c8edbaac39c520bb5ea96" },
                { "mk", "bcc01ba2ca02edac165024e53823baed8d1bdaf68cac373c1728e87f9fbbfc52bb85870afb7d21c0f0e2f9529bbcecab622e2d1ad673f4250cadd9ec292bf486" },
                { "mr", "960c695ee93518fab43461289c5f908240e46d9e8ad8559aa64e9d1c9e70e64efd09bbd9a6948b90cf0074ddf2cfd5e433168a59fc3d124530898fa3e0be89d4" },
                { "ms", "c1d50bc026420945a9f9ebefbe7f325cefcc5666301239c33e25e83b7fe9c3f089b4150926aa8f0fe80a05afc99fb50a1626a73c984ad483a69538f52d6c31ea" },
                { "my", "8b2938b410e575e3b13977d8632fc0f97e04fe43293fc634d0a4325e1895431c4f9009f9a15a71f6f04d8309c5fa6bc1c1d3fa7d61c307a3a64de58e735a948e" },
                { "nb-NO", "b015f22c3e1564587ba59bc7986efacee36587d70b33ff76dfbd67364f2966146464b1f141620d7c66409dc8f4433b5f4f4eabefde107be6c3201934eb73a001" },
                { "ne-NP", "17135cbd83d15611794f3c3fbc4a00c8e98e635345a575124600aa0d680a8870dc0e527f1cc038189d2772e87ed344835d3c6172e04ed48f69278135197a27a7" },
                { "nl", "2cd2b27d0d4ddd8ebcd4a7521e0bb09f88ffe4341bb2a60bfc7727285030755e6f1c77c7aa8eb6de538516f16e268ed70db5f2cef691e0824921dcafd5da8e03" },
                { "nn-NO", "7a6864b23682587ce54ef069a36aa9396abea80b16b49a0859d30b3b133dd9dd1e08fa71cd6f4373000f697c0e98f0eaef0aeba3e6d92262fe8407961ef54208" },
                { "oc", "ee5c088214bbc6db78ed5fa4eec521abcc7fcf3435380c9f2268cee5e15b08afb9e26516e0ef93f971e38fdb0804f7505ac9e6915ef24b13068266764d1e4ca6" },
                { "pa-IN", "a403a0245335551bc1645d960e6e22a1f096c24315e1b2d181dba45b0c5f569a4667ac14d7d471a056a3526cdc5f52052bf08f3dc7eb7a0d9185eaca806b3589" },
                { "pl", "c00d880fd4d496d17e29166f2cd3fc387c7c79af8ec97cbd10f6bbfa8af15b59d0dfedd3f05e920349a1aeb7d9e9f30490be09cb489bb682bbaefe4a866f1c07" },
                { "pt-BR", "df92158386095ca26883c598a37a563c34a2468876245943bf67d1a2cc5dad65ffa9df0c1f1b4ca7caff714ac3282ca8e67ba3cfdf43c2a15c5f3480b5cf40dc" },
                { "pt-PT", "fd2408c50bd51c7556fa4ddf49d7f3b9d8d9daf8b2a12dbf79b38e3bd1b748fa8d9a7a4632fbe7b783544b78db3c4309750e45fbd25b9eaa38b43f7a7d814a70" },
                { "rm", "7d0c173dae4fd950ce464f02a2978b88cbaa3d4a6c4fb64b02c0de8b7215471ef727b4651aaac0e6160d04ef3c3150b5a4fd86b4800298923b6f856a14064300" },
                { "ro", "624a9e1f0eaf3442d3fcd0a96fbe1f3111def033aac214b8d0b6851a3be4886f4c3b318a89d216c944ca7f67e308abbba4496393ef0f326ab6264ac8a5441d7c" },
                { "ru", "fa9af9e1ead9db4983d106a3d36858bbd32a7019dc5aa1c8249e303a3420fee82e8342bb93a00277bc727b6b5108c5dcf22ba0f1d9f1e37e426117d9fa5a9599" },
                { "sat", "7ecfc5d929dc4bf46416400a64c7dbededb546dd964648cd6f21b661d6fdaad8f160db64cb4051d85048165e3d49b28b3f6c162bbd297bccf0440a7482cc27da" },
                { "sc", "64aa73b211641c43f1f860dfcdfcb9f5b17be3580683b642eb151d546e0c8df2deac6852b0bace97b91b641822ba2e15ececf9e35f72de6a323d2a2fdedd97ea" },
                { "sco", "8f952c295406f72d5c291e6627fd26d0cbffd907bf27633844206f1c78f2969c916af06d22c75b3d8b26de1e0b44546d4ac1c2e0446383e02e64f5830dc735c0" },
                { "si", "484aceb3b8f8e5a8ac4bc66d8e6e41dc4b02a4cb510484e519adfd63d48b21b4c4e6fe3d232df0b2fb09b4d77ae0f36fb59b5f0a1d73d8b133b839588e86c433" },
                { "sk", "75d01fef74d33dbca2297baeccd88bd32b439b02ceaa8cc362219951d028bc88f42ae2dd257b45917bd0deb245851913958d77310fb160453c2bcb27575ca449" },
                { "sl", "09b64b3466f3f06be386bfa304f69ac1d87236bc1d32d6bce78662e6075deedce04b406a6c3d6bd8ac83973d6ed7b13ba192e9acfd5c68f5a76eeb31a1dde2bf" },
                { "son", "b468e1739567630522f78ed82e3ed07464eea4043aa001ffe70c0239300f191bbad9bd3905b4da8b9195c130665d3e5d09cf0d9485f29a7f56601148d47b286e" },
                { "sq", "2cf924fa7983eb43953b230384ad4e481d300bb696eec5dff9464a2e2397560f399048b09137237eae81fb91c4edf90b15d866caaa49bc8cd3ed5a14855fba62" },
                { "sr", "464846d930d66acf9698faa847e26df277b66375e073dcef7b04e14d4352c0d5690d8573acbe955c82675345adc779649c37df2913430b76be3f91525ea560f3" },
                { "sv-SE", "4843c8a8554abfcbb5fe60a7c090e59c7c433bb9afabb4a61b47b7d513fc4afaa2df19ebd95c3983978e9b62ae5c408f59f9f987586c7d92bd8560d6577d7004" },
                { "szl", "fbc98653c15551d4245d54b68f9bd410a89c430dc554d6b14662c79fda337155e69e22f952408c2f681809952247a3636944076e4ec9f0bb11b11ce9515bd64f" },
                { "ta", "adb8b41ff5ea313d1bc829d7bf6525bc3467c8e8cc468c0d3dc75609d983c8d949f43712658bc59eede2a7d3074dd64becb615f19c76a5e58bbdfa0a3994d290" },
                { "te", "9f4cd3b9ab70c4328211f31755447924a8df2b1c6c01aa5a1980a47dc775565b138c1008cf446dbe3feb60046625b02fbf3a98a2704573972924ee70cbbcf4f5" },
                { "tg", "e2a18e52d5559eb0f8c77e055eb915e688d95f98f8ad3c3e8d488cd4a1419c488d8d892179b925d0bbd3eb2b6e8a1a1b6803953c6964c16d25424bf49b33d192" },
                { "th", "b74600740ce39655e96621b91349462347d3ac2d06ae88754187083892206c9b69aa9f67adeba77da347e445c294d480fe662cc020c9e7d592c59ac9a4c9c12b" },
                { "tl", "2c204b35c152f7b60bcfffaedc33972b8f3134f9e3d19388044ae573312ffe9f2e4910781c555cda7fcbdf1b68faafb536ac3eeaafdb1d02c99a2702781a7ab8" },
                { "tr", "e34b30824ef50bfd6a849b9df31ce7040d87053f535a0f630f6411c3a43ba3883fbff6a2f7bf622e801f09f6f2ae34c069a90a953ed4a479879868d247a59d2e" },
                { "trs", "55264f821cd06dbacdc1a3cf074975176cf90922c6f6d16385b3b05841e49894da97bca9f4cb2700e03d48575121fa1febc75eca9ef6db9640aac961b1178c08" },
                { "uk", "940e9779eeb0111acca0d164b65f3e21d0499e0bd227b8d3c24022508d00efa295ce95ef9e7b311e260c758a226eb577c5bd08c078407072ce9c53e5c511cf72" },
                { "ur", "6fe8344e21c771ed43ea99803ddbc51e1988e97d9581fa4a864b811db5eb53fa6a51c0afc2aac1db24a90b562eb4d959adbf71007b00d801d7a8b05ddf64446a" },
                { "uz", "8eafa32daceee2b8640aeb9b3fe978575a827f55b17ca8e2b7fb620cabb7949c1f8721e32fcaf94aa50796353664a493b11e9ed59c37a48f50ce09d39a17bd56" },
                { "vi", "609db1ad09f623c2f4b0e83dacab54cf3b79f6c515040de25411d68cedf1f01e49e58610961ee71ba96e4f47d2710549fc59a8cecb9ab9773a8a961d196556c1" },
                { "xh", "38979f10fcf378201c86bd406b90a6cc5a4ddd42950497efcf4dcd5e2dd8d0f87af9cc1f72d0ec34981e8a53d884069585d3e51ad106c3a2c0fe4f2f55ad8f87" },
                { "zh-CN", "46ec0763312022e444b0406e4847a83d2bee98c309767773d56383ae40cb009fe42736cc23854250fba83062f06bae92e34c9b7e92aa23eab8c954fae94622f2" },
                { "zh-TW", "3f0c258b2d160596b214f39e105f094adef86db0cb3cb978aead65731c20c5a16ebbe371b6bba5ed3daf97e8599dda74547940bcc64f1519990741742a999bcb" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/122.0b3/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "566c711c4a78f88b161578895c2fda3b3a6064ef55e52b52dbb126fdabc9a4452a0889a95157c28e13d33163d374ef0f38a10e718d72fa7a93f3a77c74209f32" },
                { "af", "e207a24216a4d309f9efa66fc6d76aa39da8f0a142b4938104cc77247122343b7550ad3655763787f52ff2598ed8f28dd68832b7519680553c2410fd8f452e96" },
                { "an", "c81ede5125bd97b59d1458dc8b0581884a08974071efcdaf5ddbb800a47fa8c4b60af180c4f7f53cf5916a917a3a6c5bcc4ad1aee6c0234ab7ef72f176ab7221" },
                { "ar", "39449d6547f98434214d6de04089cd9d4a28677cc3d9b9185a77afb0546b1292e671f53424090229a19e2ebe31b75466fe388c00e105c4b3bffc03d677f1b5a5" },
                { "ast", "b1ac7b6015c738c9d2a4a23ba7739d10b0f5a865c00e26f952689092f05c57dd0ec8f29b020265a8284ee842f03dd0e0c5eeb2bd6b6c595633c9cde74a7e1ac8" },
                { "az", "a30ce0ae686b3391a5bcc7822f7d987f8194c01bd248d9378349ab8a29b32305eabbeec387a000afaf9e5138dd1b0a562bd0775ac63f3a3ab84b5110c5bf0a09" },
                { "be", "0a8ca0f25d03300ca6c6295b4724373816dcf6a855ee4fee21e2efe4f4769a68781c4e78694f66ff4ca4edca266d0e08fe1f7d10d0891410e5722cf822c6a547" },
                { "bg", "733fb11751c3511f5dfd5f1f7694ba6a8e89321fa102683f786b0a9b0683c80a4f745604ef0430d08430a21152db51474618cc1f608ab5c4104a21d3e7358084" },
                { "bn", "5527cacabc6a3e19e6db5bfde828c688b9ee647d1f69319f18572aa42145fc150820c21a8d31591f642a9cf23b2a5aee33346e138039d32a29448887af7ace2b" },
                { "br", "d7bd15d9d86b3aaac5605fa2f72dcf583170df4a7686f361519245e562a55e5e4f146e28bf208b096b44f53666031af7290ac85e74e9b290d05ed059e44f4f10" },
                { "bs", "83c6e655524f1ec13603d29760eb6812d6276dd17a2c5b938ce7c2741c3879f1b868a46f2323cc5b7881d5d58ad6e7176e2abb647b7d1cd6d4fd7880e491a2c3" },
                { "ca", "273099db8b06878f3628910033c0485b4955f85b7a2f46dd857fe13f3996ddf192dc9fee33601d368619579dea6026ee687f11dc6aa0ce8a5ed18d259c7c0b2f" },
                { "cak", "25bfc2b1168a913000c3dd7dfae6be44de20fc24c004e9dc0812d10a73781f55212e0c9128877a83953511bbe7c7f35be0df34641234f88718b3a96a5f32ed4d" },
                { "cs", "0d3602908031364e402c8fe6c4f3cfdad4eed715129f08ed52860b07e72d7ac9ebbe025241f8ab394fbc7a88844df9f0387dd35e63d494160d75cba2354218c2" },
                { "cy", "0c85f8dc8a949676ec75820150029a57d14bde41fdfee9c1e5aecb0238e921f3bd751e737b0047dfd17f735ce7a9abafc406f5cdef85655bef89f4ca47c7778d" },
                { "da", "f3b040e756c74eb8487a34e9c88b6b719d15c1cc2051a2639c6918f223509f77ff1a130c585d68f2ab233c3015e4accd76bf9999fbcdca972a08c2b169fa482a" },
                { "de", "a3217316b1785c9e1cfd7fb378c43b7adbcbe72bc23d2b81b618c915119f62a0ae16279dff4493f15445d11023a628609ffb8001acba14185f91fb18b6c1b096" },
                { "dsb", "37520a5f999c088a448f8bd02ec9ababe0c4c7c695270d692281447482450db086d1acd4a811a5735fd8c2af97f5b7aa670ddd09bbfa7402bd9982102063642d" },
                { "el", "79f10c41a973a628afb99e6fc7b0d969105ad73f117ec30c02b5c6a8c0f48c35fa683d8bfb22eaab4425ad3d28496aec7521df5eaa20e5d8dc88936bccf7d5bc" },
                { "en-CA", "58efba50acad3dbe63b22e51d7293d05f3d00ff4c40809b1cd04889e31c53ddee8a874afeab47c065d316fe19a68431d10d30600c10c32a01b9669643306f665" },
                { "en-GB", "e76bfcf4be5fff3b85143057500db6857521337ef3b32650df17665fa18adb5b04b791c32739b2269c0c52329d0bbbe8ddd47e0b97360fb79f4f72411e4d5d75" },
                { "en-US", "5ab9dd0cad05bcf482b185f1ab0123f32da3499ca4dda55c6cd485d46b6a4ecfa2f880acbfe937cd277dcc1e863282d183d6bef5c394c30c39a6a5dd7901e1c0" },
                { "eo", "66685570d70a5eafb1289a7b4c1febbcd65c785e30303d2fe2cff3a9710bc5a627309308455db4d6fd961c88c824d8655e3305d8db835c9acfffe6bcfe86dce9" },
                { "es-AR", "1bcf3882c97889568d6db38113a93393b2f8b2001395499a4658fcfa1ddb18227fa74017e66e4a8bb554997ca060dd0014fb5c3224c808d26ffc8819cf89c986" },
                { "es-CL", "467b718a4fa82886f88c4db9b75d115a93bbcb55fa1fa85954b0c632b5b3414927fe8e99583a57c8e052ea068bb2e2c488e1412cccd3298890ca5c2bb07c9826" },
                { "es-ES", "2b1cad96d589571c3ca596fe96e9a31affed602380a12ed4c6e91164d505abc241369b9cdd708318c5669944fa82df3927c066832880f33ec7180d5219b9e0db" },
                { "es-MX", "d521b3af1c91fe55d98e5191943aab2b9204966d26ccdd184e373a60824304553aa0f3569626cb9f03ab049edad4ddc99f6819db19d1314273f8ce4fccf9a17c" },
                { "et", "d55a54b26b7ff0034a5b358fadab78a34d178f777dbfb2b06f2ddcff1c8615578212fbf1eea32dd2fbba028492dfd7ad92b3e35c29634fe86c1e85ac60464148" },
                { "eu", "7a8d3100542736241230abeae1fb873f8910c890854fe5c9c8fba690071d0ab2c55b8108809a570dd2728be35f2dc88ce4bf50c659325d9e424811ba90c6fde5" },
                { "fa", "4733981187a6f8ea424715c5f797acb068492ab789665bfb0dacf2195128be9db36c6bbbd3693d40884b150e5cab9a4f5fca1b252310cf516fa61b37e9f5d61d" },
                { "ff", "e00055212983cb034ead6d08df98bea1f7c41c7b782ff833a8a34fb2412bc43712fdc28cb2ce9257c977e9f7d6ff706fe5dab4c6dc80114358b00e572fc2f490" },
                { "fi", "631fe6f6dd854ccf173c5ba36ec98d709a4ef07add8ac3f3215e34cb666ae351245683af2d2c02edd5190d759ee95d148f6f30ea3314e7e5b7848aac498a9877" },
                { "fr", "a6016dad8e77df223c8a45682f3dbcc3319d8cfee7b40264ab94a5d6512aac4909c40064833b1206caa5905c0dbf086ab5124376651c5fd359cd2cb892088e44" },
                { "fur", "062f918ae1a441cb3de918a96b6c4b19e99e634c3e0d58bdeb0c0da23911f0bd3e35a02ef1edb88ac1e7b052720474bd2bee2a7bb760cc591b4f9fc00f6341ea" },
                { "fy-NL", "1995c61ba25e70dd21307d1beeb7a81d1094655d8d49634fff6a0ce7a42db9fe0c96ffcc956c13e528a1c8213c38085a700b4768c830123acdfb802aceb83f25" },
                { "ga-IE", "fad173bbfd2a4b092a3d694565c2bac1b1f385f1a378eaf68a81ec9ac4edc7540d7ad22245e578659d3fae0b3c01da3a59bfeada630af5365dc197a6bffed409" },
                { "gd", "18d1ae49097a2c1f171c2a9e27f9be47ba6f22d11b4cde2832ae13584346a66867a5c8ace0f96ea837762a7029ff2fad4a48b80bb597879812ddc53b009174f4" },
                { "gl", "2c264554a9e9c62781642456296f9e4822c58698d15e1f684d6430985d719c16956ebf159a724836d6d896faa068f86caf079bda17feaa2de9e36b80f3fa58bd" },
                { "gn", "b76b691e49b6ddc6fb0f08a274f00cd6130dcdd686486ac23362b3313848ca1d848e0b390dfdd09314d2f0abc9fa2d1ed7cd0dcb2711e12e4b6a430044bb8b9f" },
                { "gu-IN", "1a38dd0f1a95ff702d7b53eb0aeb62abef9e5fdf02c0e7501755bc7c70efe77b41d1ea0941e04bf9e878c223aa1c0f518f3a5d38f012a131744c25396efcc802" },
                { "he", "97ad7035b690dc68971040ce782fabf415d73091e4f0581ce3b79d963eba46cd10a2e7b9f1fcb0166e7325ebcfd864f48fac0ab54c8f25e34dcf094a958fa9ee" },
                { "hi-IN", "997c25fedc7c96c36e4804c6167e452b8252b03fc8f7fdd1877e6b2c388934998e7cb6a5c1389a77344168c8a9b0d4295d4611a02778bac1b9329024ec034f42" },
                { "hr", "6759eac537ff281a42e003d67960e381455a887461e5db8a106ed5cbe9d62d654af6ff369681253be6693e5899f3f4e2947f4578c6c678566a2509e81512ca45" },
                { "hsb", "905a39ff4e4b47426536a9627f93277264d2bd54452e66dd87a67fbb995fe1c1fc285fbf37961632da7baf08e8b7e7248a6335ed98fc0951e7757117b29641f3" },
                { "hu", "704e1332ee95d9d1e1c18393aa55720680b4baa3d9e24f20bcc8cdc410bf9234fb5f63127b0925289c8a045d2649098d20b739304ffe81a9f5c356db54d5065b" },
                { "hy-AM", "8e8b282b9ac04aff8c6d41ccf4bf7bb72aaad2dfb8bc4ad6783ca2a7d2b1833df7583595a77357bc4be67261fd0ae2e66f35ddf312fe9bebd4eb0051a3aa9ecb" },
                { "ia", "1c552180bd032086a38a4c329999a8274f2e1ee191ad4f6736472f8d617e471c7add278f2499da6f5ec7e5bbca9c9e2115342f80262b75493d365ddff4b15c2c" },
                { "id", "794a27d743098c07256ddd4199edc0695110474fd9225e820122a6d766f394b16170f95cbcd9ec728fa7b3afb3ff9475712c57f928c438422fd144ada4b2e668" },
                { "is", "e1a24bd2c3799b8f1c32dd10f5f5f2bc6091463e6fb06a55a695fa5202891cecdf0e4a97a52a59588db547eecbeb08f3f0ac62e30c6b3ba8d362bfdc5a295db3" },
                { "it", "fd0b1e1b526a65f8af9ab77e31f761f9d0ae2064ea3fed88f53123c7ccee6dc21d870a5ddfd1c1df5567166b33f9bc4b1db3f38c2bc9b2cf482c7a7cf50da3c9" },
                { "ja", "7840632abae8b8ad4f0877304a3ca18d2bc2863245b65921cb66ccdb9f5db3a7e3ad4a614761a8a3224a3058410210570506cc5c6d18f3952c8b637a5716f689" },
                { "ka", "981e2178c287686d43ed6238aeaa920630751dc729a3cb79893181393e467f977b6facf9e53a789b1026ce80a46dcf5760974e2d19c3ed7f03bac693a4ddfbc6" },
                { "kab", "75a8d4704ab4ecb0bdcc2134e32d417d4b998135bf2730c8ad31aa3a83ec66cfc4a2d4499340745476cda36cdff92c8ecacd660da27042123671cef4a7c27d87" },
                { "kk", "e8970928286e5ef1da12a396ab41abf308cb6d997bad4feded9daedb93ba0b00a542024df671e3326795681108ba9394d4a98718e4f6dc4eef2f68c05f8a48e8" },
                { "km", "bffe0a1879e83746835cfb0a645be0ce260c873f6a414fcc97f64a110444170117288c17e629167d73786a5121830720052185cb61126557225ebaf5b1116b6b" },
                { "kn", "2389429bc79a72a569854b51485aa3f98a0b65c5a3f642250dadeb5e1061e40494b5df1c13aa1b342e115ccf51b9c1e151d1666c746edb8b56300d5476dcd210" },
                { "ko", "5d36fd969bc3f1d20948013fd39eaff35ba8ae1055537a80d268caeecb1a4685203c6ca08dcb643a5e2beec4172b2c8988e782a02f4a92558e16397ce6947763" },
                { "lij", "3dcb608627bb52c7305edfa004b898de1c0d88bfff21099f4bc260826d463c049aa8cd441017a9f16e4ec1d692536581f84b0ec3613f31792df8a40f8d5704ec" },
                { "lt", "5bfbd5afedba9bc997696576536ba122fa9e27240cf70fcecebc292ca604c2c945c3361fa8abcb0077d14621cd0daaf83bfcf8d20d7da5005f3953a8c680fdc3" },
                { "lv", "32d23a8db0a530c508906ef961ff0c43103f7c4457b9d4fe200d87f4e7f114f1e14d321cd93da9161eef7e31d564083c52ffa4daebee894294b5d95268246ec6" },
                { "mk", "5a1e6ac2a8c118750e1f4e0925c53f8b32db7c31d0dff0aff0c35a63f3a430b03653e92768381c8a840c837bcc13d1302bb512a23f4564bd3aee24021f8e6094" },
                { "mr", "3515bae5ae5ed8834fb3a2603406fe2fe5f85786e0ce250df2669498aaa999e4465cfeb40f602c7e77f49db9790aa340618d0963ebafd744ef05893036e7dafa" },
                { "ms", "b4e5a2730b1c065abe658591108ad6082c77fa26302f1bb5254020bf0257bf06709a8b1861d95162618303dfbb2667e55517de307c2537ba5d47953937b8ed5c" },
                { "my", "3401770597f4b2ced52c071eb7316188c987e528b57b10b2a8bd88533349ac0dd040b9490efe555a6d5409b24bc5d237b88a2f00dc8730d8039821d04d68e27d" },
                { "nb-NO", "ff8f712851958b6de177d666620c9ef3916be441e718c73a937b0c54fe8c9b2dcb4ce631d9f9a60b8930dcbfc41e84f4ddbd82db7e490a2ee13d573c010ea7a8" },
                { "ne-NP", "c1202cc45ab1c4788e07a477b43dc289adddc85e585222934060cddcbacdbbc6751c129d17276f073b0f57f8779e7fe63d8f941a10cf109baf529dba198afa4f" },
                { "nl", "829318d56938429653a2b2e401acd95b373fd4a45fc32fd4e060cb4216f7888ea8673bb6597eba5d787c47372f48025e65c5a3de24ff505c174a9e8b1281b946" },
                { "nn-NO", "b6e3f8598fe56f8f495b6f76a208aa3df27f4fbbc683df0a6e3644c174845a8b89fcab6afd082a2f5d59af83832ed65e14bc0b50270bcb3e88aa6cf20bd02adc" },
                { "oc", "f2dacd522d35fb917d3a0b8497b4b39bffa195205e55e966c6a0c69717b84cbacfc40b867740613922239eb0cfe9517b4b6d86a9d65ad61fbcbae53f0a208049" },
                { "pa-IN", "be1f59f97c50807b8abc9a1119b5af3a84dffd4538cc0ff14ee055f6f46ffc1b48e41924a83816b763d6d32df11331c1b254bd17583f3cc99f9b6dc461447ef0" },
                { "pl", "24e6e6f82a04c1d3c42a3753c431bca0b2b5f840b53d7a64d7a1edabd03207ef9d3b2b65c04cb13babbf2a09238a76937fb5f27909da4e7eddb79b9541c05384" },
                { "pt-BR", "cd3a4d01f64d4b1f5deefae75cd1533016a9c2c78d96fe524a4d7e419e705935eee53353c811edfa1689424dd851cf0f05e0b28425594e4df9560e091fbf9af1" },
                { "pt-PT", "02af6581e2f8aba297b60e150494765323637382a98042655d9acfd1caa9af359666cb6baef8bc33153c070b19a5e6e841f251239ab80a2756f9a6c68cb8b803" },
                { "rm", "1a3975837936952e1bb7ad806c96c54d6039108204f37f133195091892db2427fe1a1e4d6dfd2fa89d67889ae818e0ec3d50410dfe9bcec2336435e6b43c64e5" },
                { "ro", "f9a3bec807ba3aee701c0b186d65ff4d931b81fd9f73e88031605722259178264295067470385177da211e3a1b273ea83c3b537efafdf85ee9d3ffecf0a5084d" },
                { "ru", "e6191040b91a1b994d5dba76b1f3d189e3d04c3bf46e21b5df453a4e829701b2a6181d109c69985399ef2c80236a7cfe580132e9fc74b90a7e818feedb29430e" },
                { "sat", "9e348bb032139bb90bc4ca10319772a346d4081480fd37fe50fabb3c5383b48bd5ed52455fb4ab0af3984e9bd3299732baec188b2f52763646f80ac46360ac9b" },
                { "sc", "8169535851eada56153b40615582fc654398f7f61a88e9bf1fd06a341439b9f2ddd5addadf504af6e5d61a0c45d7d56e27e746c27aa15c4f3f49a63fbb59a33c" },
                { "sco", "f35bdb49af370f54f272109d3cbade10f31c501f14c577caca0c2122c5679a4ed836a19f8198694206d592240e0e5f5630ca411f90c5f1460af42dd8fd80e887" },
                { "si", "2bd6dd00f8e201f4277657baad009a424dc36bcb1dc9ceb6a73ab7fd3001e2a9b036b979e578ff60ff966324ed9b8649f996d8ffefec33a484fbf1a17b58098e" },
                { "sk", "45ef0c73818dcf6a2706628735175938f2b62cdea6b7b831ecac1b6b225cb6d999a9b0669d9206d52e5125d0a2dae12e27ff573219fb2754205a1aa7680e95bf" },
                { "sl", "e2650be771c62ee2bd897463935f4c7d6c33bd12a35d55cbafa9b06afb30ba2e534807a1f6fa4d353c4bf388fdfc9b44d2c7dc8e00d4a3777a86c2c52a9767a1" },
                { "son", "afafc0ebd90459cad2d48871b016d09b921ca95114414386f07f697fa37f4effd31fc50e16dba5927fd3585b207a34284863c4233e36a43ba5ba5afe92df5ee5" },
                { "sq", "2ab39d85edb41995deba6d84e663808f4546e29e4ac26331dfdfbde5830f7dccda1516cee20262cdf7d083522eb4df74dc54175dd87eac73cfd3f4b7116ffc85" },
                { "sr", "407bd4f17da3643f5b87b554d3301d87d2ff11cf0a7a84edeb716320543de04063267207a36284243c6d485fe2a05de5c8359c685eac1b0cc81e91392a90557a" },
                { "sv-SE", "e12a83ac55917a196d6540d71a259fe15f9860f807a08eaad4d6226d48b72c3078305d1b25ba7c27fa4b47d024e1002b1223da798809a32df7a6929a9b977cd1" },
                { "szl", "cfb7a44f37c443724f4a10726c1fad4a57a10667052751559d34e8e205c1558936fad50805b9f55e8d74d893415d3484b1bd09755b923d164850620be850dcf5" },
                { "ta", "d8e2cd4cd5423de0a00ae2e9f02fcb20b4cc2cf86906fe3a4bf3c08e4935648b2f99356b0fdc2054db9500460aae6893446380ace1791a8d512895e371e64629" },
                { "te", "be19cad2b5d909ce419fb32a8e48fc245152190bc163b9d91b7c4ce6582617e7dca415b25a3574238f5f35d58732ff9ecef9944232e93157d47ffdf482133f9b" },
                { "tg", "98ab96637ca236615df6b96e453f362934dbe10455c1fedfaec2af362f4d120b22a4f5c015aa5dd3fee32bfb7205fd0f901a7d3c58eb3da4cf5e23121e889832" },
                { "th", "0805040bb79f38318cd95974b02f8e07b36dd42c34fa42550385587f7df81a80d98d552639e8e886ce5d285c06df19983baa356103051466532e9ae78db4f400" },
                { "tl", "492fc0735328d3a60d1cf5273cc0face6b8b4957afde0e00f0e232c74f97c8f7c4ce70cb7431facffdd8db79b5fff8b8979dec6ba5fb7c51a0ef0e4cf4b1781c" },
                { "tr", "f21a1a94e5625169ae312be0f9d0c04bd5900f9533a56e55cc9f7cb8b7d1b863971260b789071f96e6897327690a7382373053b09195d0a8af38398da129e7ad" },
                { "trs", "f24c78069a71a2d8494b2dfcd57d38b9123063428e12b76b5107203c501497a55bf7ff09f5399e065527b6472307d4affd3d10a4aa064795fbca0a9f42eadaa8" },
                { "uk", "b1d7c7ec658916ad013834ffef23c9384d3b03f96a82c4740a10ab11652042484c4d4aec1d0ca3d5569a4a2c6c50ed3afc26c2315e4cc5caf16ea30b7eaad095" },
                { "ur", "37080cd6fdffda257a0d6f4c128505ae208508c311d25b7bae8ab7c1a2af1c615717c035e0fc95744bc9c76a9a19fbb0008537cfe8b16c668b3d1121a5d372f0" },
                { "uz", "cffc729a6d2cce520149b6883155041764b669569c500835131975ac569c5b467886a107363cc3a3099ad880a7ad23b93e302d975aab4d8094a3b185aaf2f491" },
                { "vi", "e578d53c7c948997a08973e6d82ec354134260a044044ca79f3522b0279c41601e64de69e3d184bc5ffd94acaa48cf084cc96ab5c92c6ee64764f68ba8d1102f" },
                { "xh", "0e593cf3ff76eb3e60a8786cbbc8082db81ea8032a364adf34048c54779d64b3f62c6c4d0cffb75cef10ed92b8190f439773800deb1fa289870ed9587dd790ea" },
                { "zh-CN", "533f22a105ab8d3cc336b56cbaa5f2dfd5c5c49a91198da5ff234bf5ae61bf595ad2818e0eed4020dc12d8a7756f49fbcc03c15214b195a37fd01fb039a0ddb4" },
                { "zh-TW", "bed473598c2af584c0bf65534e2c26088801566062735bc42ecc4f06eb062b61e88f9895bee9f88b06cdac65c8a4ad5710f270293f987c90393aa1c0a567a9ef" }
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
