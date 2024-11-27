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
        private const string currentVersion = "134.0b2";


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
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "255bd796984b87d81fb52c8d4bf32f4b136e5584a5db56c47f27f849ed24f31c9283c771e4236e05510a9ba95c20c4cd21ddb8fa88f4c888b57e7dc0faa393f5" },
                { "af", "67b51a8e506c1e7befde48374992ae3ed116d3aef9675a6533980ff11351ece063aba3aff38f1e395b67f1c7a470fd395ecaff10045b3d51782dd2952aff0901" },
                { "an", "725fdea097c71918da6c402ece897c1066e8f050cef5ccc3a4a743ac3a5cf3450bbb7b33570cd45a6b672d9ebc9be9b879b3aa384f7da3e078e44f119fc29232" },
                { "ar", "cd8509eeeced471bbcdbe42da95991ce21e8398fd6d7f09dbd082f555c695d54eda421da6d286a4af2344478f65bd0e824f055dc6d32f2434cbae0401ee1fabb" },
                { "ast", "43c24ee8299620aa1f6cc4179415a53a65a40e5b8d3f72f13cb9e8f45ea2c0d2e16474a22bca25f6ea61f09af9ad61bcd28651271a106fdfb9a29058b6593b22" },
                { "az", "f23f03d08dfc03686eb4a20e8bf65b7aba4fd6e46f1e6caba16a2e41595778af9d93251d69d6062390a714df2ec3febacf170bbe786c27ab7e44fa2bde97e31b" },
                { "be", "8af0129e7f76dd038c6949ffe191e0edf796c822c944c2c0ec55e0c7851821343bbcc5f439ee07cf41f56213b3e37f4c094aa3bf623e0afae580ae7f1a82de1e" },
                { "bg", "a1b6ecd25ade24e6a20ffdf726e368a6fffa47b8abee6a31a58cf125f40a9ab26d9e2dad57c81d84f3f8e9966195109f39c74aa704895459fa7e416021dc3587" },
                { "bn", "a71c8ea71a185b5172aded33214358fc87d11136a9190175e6aa915a062a6d86eb9384d407b2c4356754130e6a8f3ee24560695325fad6c6a3613c608b7cf6f1" },
                { "br", "148eebebb6021f198a66eabc5364cae8970baaea27cfa620c436807df449057c0749a9a92f2b656020def285ad4ef84101884513e3146a8229410f131e213ad4" },
                { "bs", "1d070e5e0f60cb0c5edc58b99f14b2ad284b4d64ddbe4edf54ac2ebcd827ec4404a4365145dfba46e57c6a74e0ac729d8360e34db20cb636074dead4cf886b4d" },
                { "ca", "c201f4f05ab0e2d0d8e1eddf3c9043003ec0ad0c8f8943cb277c990cee9eb06ffc3e6b834ac1c19fa5c079b85429eea12750c74ad890abe8735df7f7f2f6c359" },
                { "cak", "82707f18582c3b68fc11595d22177dde678ede0b4a5b69ca16d3024f33a0a57d2bf117224b02f07ccd686a146ac7a9667be4f1b0017939cee51c1e900a229919" },
                { "cs", "3833004b0b50f20ccbcdb8bda2675d5914c67a4485550c412424fa17f3b0a4944c9de8e58de3ab7c35dc7bf36c9e4cc9b9ce69fcaeb8ce5b556376dd8155464a" },
                { "cy", "6715dbb72018a3c52a7fe103ad4bcb751da18c27cf2b1ff70d1051032193fb755a7ad6ab310c6f09fe51800fa24536fd1ac06eb567fce3c434c31a2fa9d3ab0f" },
                { "da", "2204c681734e5d21b66fc232c7670d1cd5e91a1f13718c90d8871f4e0f6279be0071ede803cc6b64163b9eb68ab224fbee6b2389f5e24836d191c039dc45ac93" },
                { "de", "826e798bf823e86c9364ac5f019b5a0d105d42fdc867f8270dbb467bbfcc99cdeed2404285ac37429cb67dec4d55ca6157dcdbdc6f964e76285653de4334cb31" },
                { "dsb", "c350384413a606a5e762864b33206cc0ad4abe5062d17db70103170d9054c5928e8fe208fb522eb43e7b2c629f57511ff8ed9d70cbf0f8824bfda05aadfdf58f" },
                { "el", "0cca95f91d89599e76280a474c6f5e003141393887a817889abf2b76122281b81a6fb27ac5f625d1e4f22e4d183bac3986428b31dcb686ae695e20d9ebfb1ad3" },
                { "en-CA", "0a2d4dbf5e6c7d5ce4e7a23b49f28af4ba9034f6805064972675a7a5f6e1f20bab221080d6343bce6dc41d2c12ee9b33964c5c08499cdcf568b2488702cea221" },
                { "en-GB", "97159d96b95dae48b3a7f9f9ad9682413ac29a51199124171269d7ee64379dafec9b35f0e31fd071c2ed3085403ddac2dc11e66f6a2f8ea9ebb1c7b734bed85f" },
                { "en-US", "ea62c9ef1129f28001e3e2dbaf9f65eeb0058c335bd5ce61bf570bdb794256c6f0bb32975c1f4c7646c9dd0815120c773fbed9c51b6f24ee41c8b64d3bfd54fe" },
                { "eo", "9e08e8e26fe77bc55fba52e56920f01c885e5db6b5a397cc5b479ee6b2edd5c528bd11644a594dc1b6b3dc87bf2df21c01a197c7ef11bb96d231414c238809a7" },
                { "es-AR", "2d0bfe6e46eb5f02e82843ed29b9e4b03be65f3eee1f2ff4f0edd537766e2c09b14630a0e907e3c77c6ff60bf4f72219ce998b837a2da160e656bff03c3773fb" },
                { "es-CL", "f7a2e1bf1374f0719763291c09dc5af774cf8a0e2ac05494a137e18a6363663d796246f8fc217d301293a12c7e5e4b2ceda7c70d60c9d40044e4fb9a5de6f381" },
                { "es-ES", "000ec759f2fd94e1de75cb8ce065ac10c6b80a23fde0f0f1e7ac28a08b43885f3fae0e5c870fee2447f45f1b5e8387ebf7843bcf3a37ca28625767cde5359149" },
                { "es-MX", "7fef44173c7f7ff5cab00de507401cdebbfa2ab645fb97ced15106f06f7593b0786a82e34a43da70e85138756a99e4a8f3f9122d591c0dca8bddd9832db7539e" },
                { "et", "8fd1dd4cc24dfcf4edb23f286e9e5ced66d52b73a2b463142fb664f039cbd68081e1f455a13fccc4c30792e75e3aaa315465d2e3c967dbfeb4d12c04a46bff54" },
                { "eu", "c3ea479603a1f4b5914a53a51de913386591a4d04ca9f06483bf43e9ce0693119c8c21179b78735331bea1d8b9f1a9181c966c8162f42131588c4c843d44fed7" },
                { "fa", "1a6517eab9bdb2118ee81dad9336dfda87edc7c30080abde40b91abae8b24c68ac2d402dfc98a48b5128dc920f1d2bacb9400be6a2363ff5eaff504fdaa35e7a" },
                { "ff", "612b6e56de20d0164d7592999fc3b8d36fb589bb31b696da4ec4a518e144fe35daafbff02aa1377118e1bcebff37917719b60a500e17ffcbee97dc4d8f44dce8" },
                { "fi", "93263c8ad7163ab854aa85f2e6bdc640abf8fe7370c120c4d6c6fecb22edccbdd7a513ed0db27edceda6951fa87a4c749b202f6bc19648139800df65f0cd9aae" },
                { "fr", "96c237f5029549fe13d212441aff770770a8a9eea92bf18d597baf7dbe46514d96b0cc992451e33aaef003f3b6cc8806bc301db9c965d03e199c3a196b566e3b" },
                { "fur", "794059be41f695fae8c441f9d5ff9a7076f4b0b38018af4a4e36d079a88ba6a8c0aa016799758427ad5fdd8f21dd2a9948d22121f22b8ee014abde55a92ca397" },
                { "fy-NL", "99d39e5643ae560b9d4adce92bdd30bf0009d7b32d84c9ee9d1aa07a761d8506b80d6349a11977371288da41f67cc91bdc58ac7228f681c58ea438fbc35df3bd" },
                { "ga-IE", "e5a95af255640fca48bdd829ac79499622bec46d850e51bb8af0f2f67fe41292554e9ba009063e6b6f834fc38fef7f31e7c0e6c9de54b54703539029b594c52e" },
                { "gd", "70c38067bb3972513a26172cc27be3f20cfa6cdb988d473c7994d3a56de5d0951ff1438da0b2974b0c03b81f376c88e0c0b8e4d9050dffb3eed6b3ac3f9f8b1a" },
                { "gl", "f3d6f816b4a577e48bcb15b240abf2d3019dbb4c39da2b207ce892117215d7ce1c90f262d84886353efb947af96a573ef721ee35a664eac0c4aa3f213b77fcd8" },
                { "gn", "502dd8e8710eda51345ed2151d1e46f452c46d7167504ca673c9570d046d1a7f49bae874198f3b744f56e485045716a2d9339fe354cc5e2a0d0a16dd0b146bff" },
                { "gu-IN", "732b5c46cc903e2ebb294c919ff86d6fb90bfb979acbf4d149ebfdedfafbfac1ff90dd1416ba6f135b423e206b1a4e68ffe9b7fe1c1ee446214e5885a1d160c6" },
                { "he", "69f7861985c2e7bd5795700dc4e06dba2e8e5c9c83271f1628220cd7568b77aed6df4972d32bd256de79a15dbd3baf49dc2ffb1e8d51c6cffaee9369e2e0cb47" },
                { "hi-IN", "a3d129141b6838dc71aac243ecb10c91673e8336fcbbbcc2ea93af5887e969b72c338319be49fea9ab0e068a2bc502fb9821cf3c7e38bdf1a85a9dd971a49e61" },
                { "hr", "7a697815ab460371bb280acb06f1033d3ecff5974cbc8a29f47c3c68d00f34e39d98ed247e98ae4e1bb34fe34a8b423356ba6df6224f3e280712cc9758a79122" },
                { "hsb", "90d5b0a5b3545c9402f260ab78647a088c31c7593b7902da62194fa3f25b518763b5764c2d857399585a61eb0fa828eedaa21160601ed556438fdbde7b3b0fae" },
                { "hu", "2fe5fe22f0b9a4080ed98207d42c6f4520c74312112190d4cce18f646a85f37562a3be441fdba14c627f620c8336b24dbc6d7e6432e5757a896e4357d0b368ab" },
                { "hy-AM", "c277ccb3938024452835abea1afe42d3b3abfe324ac89cd5e60e79d749ed1f95f58e601e497ab4ccad8cc83f07d0e639d0fab3b5acb47ce6945306a80957707b" },
                { "ia", "20a52e86c5f11603e2387061eccbbe16e24f313d02bace1b792cb82a212825026e5ce01356350af8499d03118183f9ad616172b130cb1c51152cfa9ce4cf027a" },
                { "id", "da58762d086ef51f048bd3c611174496464b8dd2ed9de2680a78fee36da38ce6d547345b7c75ee444fe8d980aff376275cd8b5991a8bc8c022031a3e5ff95588" },
                { "is", "764cb6d1019a355ab7770d582af564ea9f9d821e83f58afc69dee64aaf873657741e74709070db18cc3074c2a1d7cd5525455b821b103c59f50852fd7625be55" },
                { "it", "48e34312916d2462d031539ddfcbc31ea11ca7caba49e45b073acabbcb65fede82a55c3d3edd514a9220064af92aacb06766bac3532e6a2603b3d4653529e12f" },
                { "ja", "c6b684a9f27f17fa3374f172d356ba71b1cb8384bfbc2a2a4f7f6b9a960b5b7c4585f3b060b0b5b50e00f5bbd3f5327630361a900754543025af0387d492781c" },
                { "ka", "7f75d2fd8b99af3c18e3dc3af4477ac1b7db9c4cc605e347a79c74f0df68331de29c4d738a6aa6b07cb2193de5aada5548177f8db3c7ce3f476cd9a6d82b1039" },
                { "kab", "6b4cf940231fa6c2b510dd63510e4d68b187b4dae2dde23112f5fb15324bfe3d7afdde722e4867de16eb504df8035546a4de775afff45414ddb46002fa77c39b" },
                { "kk", "4a7b2c03e887b591ad0264a1c8983c372e75dbfc26e62a901fb1a45ea673b7198926fb0f724b438bc0b76d26ff76918cd9a35106bf609841ec26fa0179712443" },
                { "km", "644e2a397bfe4d9509ca380822e3740cd3ade7cdd41760cc6e2c47a955ca33ed673a7c3acff29d4794c10f365e4cd1f4a061739c8b9d443a413cc256312797f1" },
                { "kn", "55beca909bc0c40985e1540bf4df05e45d12b1a8c999c01a198081325e75a1be247cdac924233f42dfad6ce06b48ea21a1f770e1eabdc6bcef1947138d07fb71" },
                { "ko", "4e027e0274de1617afa2e12228d6cef5f228aec958987a0e069f7495da6028df5edb26e900c342eb2af43405af6aef6e831eceb3ab15f157dd69a902935e4a56" },
                { "lij", "e0cb1557e967cfe2068137a0ff38fb704ec450a0f5b8a68ec86748d0ff3c5cb620e31b98c56ab9de29fadf9933a9b0eede0f21ada8a878910f47b1fc4c224ccc" },
                { "lt", "4aa3548e300dfaca429c66637d33bec26c765d9686420e592038aed188842f33dc0e4716349dce144e2d7a3ef81c617002844ddd391f804d4673f94fa8dbfb72" },
                { "lv", "268d89bc824a7a35b1a3c48ebfd092bda8d3c90810c0c52d6ce7991f948e0788923a64ffe288227ab18303e21cf1c6406d8c35232143f770990229cd2741e038" },
                { "mk", "7eaff36a3767f9712ffc2be8e610f2bc9379ff2065264aa4b257a3a3fbd61fd6664dce83288374f833e0feec81cddc32bd44065b225176da2f0bced3d5b4b68f" },
                { "mr", "1e7293d0f67cbdba05fc618c51a8541368c4e4c5a89db791c1a95e1d5cd8d5c7f342cccc4919a939abaf14f45f4846bdc85865f208a15b2544646c0cf385019e" },
                { "ms", "42affe661e1ca901413cb78746ff8280d469158c69ee30eb3d0079b65d9b6988206180f6404d3f094282f54a7287334332ccbfefb2207bb995b47d7de1b998d8" },
                { "my", "878bfd6f6a9e67730cb89a3e7d7df93001b615caf025d2a7b4cec342ec3421a4886acdc35e906a6b744b7f9f0aaa91866577ddda5fefa032f8bebbc5bc1d3d97" },
                { "nb-NO", "45009502dad298127465b6deb6a06666a1cbfb4bbe8447cc0a1c439253d4e43544b69747f7893709ab8b22f6c1f339f342636e453b3f133baad9eed4b3e11327" },
                { "ne-NP", "fd1cf8daf00c4540107f1a91b289109eb72d058aa43d859d905fecc4e565a3c8227f992fb7fe3f5a23095b96cd8064d1bc76d93dddefcac7391c322e0f58533d" },
                { "nl", "7fa44d83279140b0563fc9f0e2cd94a837d62dc24f81a148605fdb02547f86642637a36e7c085b834444b83b2ab7400fee5211f033b52604fe4bbde2c519c9df" },
                { "nn-NO", "619010d8d973a313631297e293718004ed3e9063c66d5880e2197b38712061787a6aef94a813b928aa2c1871d8882737553501ddc4a2882e1e75a0397cbb7072" },
                { "oc", "5991999ba85b7870b1eeffe91d2387e5ffc39bd2557d4427d4b1c171e5cff0c15119afea29bcd092bbfe91a25f105c558aca65b1ce11959608d0e99b037311d1" },
                { "pa-IN", "b7ffe7bd9bdad01544bd0fd8a5131bc6f6d8ddecc17d10743b0104e6e73500ef612a896f54511a97ea45910f9058b6a59724b9bb67d4e92b4cd8ec784113f088" },
                { "pl", "2362259447d23f44cddb9aa9301ba2a49c48b828e5f5f4c7d11493eb70f8599e2559321e4d9c7ba5c4f4dea779ae2a7a9f05aa4e41d482eaf7cdeba0938557cc" },
                { "pt-BR", "22bdb0c57583290a26de5a02f3325aeaa4650121f69d3736d76c6c6e302625ba380c05dd3e47775635b1c8f58e9171fbc07ce976b37331a3ae34f1d7c606e8da" },
                { "pt-PT", "beb388048a38e66c31050dceabc1db1670773478910dada6c861a35d6136ecc7abfa75df387b49bae88f86dcf88316f9e6ba7cd7497e0df8c11e60c53aeed6fb" },
                { "rm", "c644cdd73876e138087f2ed9962338dd2991ecebd1e93e2c50632b4ed027cc638696431f247bba15ba46c622c86233bcb40f484f70ed0b7ca42ac09a79952e3d" },
                { "ro", "7ce99fca32e708530fee2c29d77eff06a21236429280fe18ee7ace9933b84e1f4532cb496f233538029b74e837bd04174b1ee28ffabf03e8f18ccdddffdfa394" },
                { "ru", "cf7a8901cca4f5bfea32a93e308d6e4befa3bd986c3aa9fc5be54e0ddb36ac9bddd19c8cfb30837738afabf009f7fac1bacc079190ca56352fcfddad127512e8" },
                { "sat", "9fb9ede112d48a0bd69c505e89f20d2d31ce86d3271d5c32dd54b90ee2400a38ac7308f033f7a99909c1e9afecbe8ce5f01b5b18cca42aa89e19703e68a34067" },
                { "sc", "9cfba0c06d6625d0f58874eff8867b58adb8df87c22c01c67b08cf3a996ca99cf6a99b3eb855f70da3007c0ba4df1d330899e82496d526a1a648e6b60aeb42a2" },
                { "sco", "721d3db401b17f63422a4a86f9b4dda93c0ad40c3251a53d0edb37609a40423a735462489fc9463251481997675b44288c0af8b962f2afb46d320ae7343d3204" },
                { "si", "8d7baedbfa1928abc9492e97234e477bcc83f257ffac03fbddfffa346d28de4261db5b8a79ca583eaead3a281d25d5a4db36524d9eaf92dc66ce179602b72cb9" },
                { "sk", "cfa265d702ca3d94a8b726249bd02a4835e225ea5e018c3a13c9494c0581ffc1076c1e464300ebc496fbb0fbe0d9f970b5017cff0d44063e13d0ac8b517cb75d" },
                { "skr", "d52eb3cd93a36d26822f060bf3d240430e5dcadb3a0c1aa421d5065fc978e35939ecfbe25f6f7b8eeaf0bf0aba6eb7d79239fb5db506f911e4f637008609bfee" },
                { "sl", "ddca3bb21c22910fb901d5c709096872e0ca9d86a748c2d7b18b36274a249cb021c87c98518ab215839be106c8c7e1673a0ff8627cb4c39420a5be9f8288c763" },
                { "son", "ff4e17707335d5ae6a6580dd2a2954feae2121ac08deeb882ef5dd367a6bcb287a948850781851f8004e22a64f187064a302033226b62b3b6328fc1ed30a1458" },
                { "sq", "515cd58fe526f74584a89130980f39e9949ed3a6dcbef98b0dcb1a7e4eb0265148a4a6d77798894cbb59a445fdea791f301f7f8bf2198807aae9360cc0bbbecb" },
                { "sr", "93f5e6aa8de8043b5695e0166a849ed3b433bb9b82a3bb79ae856529b16bdb55abd0be3d60a78d284f9ff55122cb228a8e8ebf03ad4a3e227bfdb5853d3d626e" },
                { "sv-SE", "be75aac1f9c54943ba30c5b7a95d7bc59a871bc494dbf3a990988a92e0faac21230e22e596670edeb060d2fa0144fc372a00a444e39a9eee4013524e493b9fee" },
                { "szl", "31cfedfa5c42869adc1c9110eb7e5afdd0dbe49926907c1c3db7dc12399416e321edb32cee87ffb5ecba01a351ee39896398c65bb02ed5976b98414df025d7ed" },
                { "ta", "2338348a5bfaefe5d43565b642930986a78ad36c531ec587b6535f7a420a14d57581c6274ed5a16b9c18406a02f918fd68dc6548544b9de053d4e2dca6852788" },
                { "te", "6f17a11fdd2deecd4fbd09e101e99aa1311f5fa54b8bc497bc31165ef8750ec5e65f1b896762f76acbfc84d86faead5496707db6a486bb6f63d77d1e1b5102d9" },
                { "tg", "b76a86128d9a034f79217030c62a668f366b5dfde4f4deb1f83efe1d1d02f7ce4688d0d2b896f49637c2fc4aec8d6ab27cb7fa84388cc8b6f093558ccb324214" },
                { "th", "c80327c4e8a5d3d990c42194f6a0634322bdcfa137e085d57692d176668b6ab6acc824db4e60bb74fe87c34970dbbdc6f2650babf4363b8f33eeed7132356611" },
                { "tl", "1c16d74e375350ed682e91ea6f5e724c50fbd404672ded702b7b6a085bad20ea57dd471b5995c35a394dee06a68cf884aa1af25bf1d11602c280c8dcbc26cfe4" },
                { "tr", "7d794ab15343dd9946aa94b88338241c07a6496f61209f9f1909f5e1c0255e7e3fb0c0dbe8f50c06ba2d9e3251990ef2ad2056577eb7c1d2428c42ac46e14e9a" },
                { "trs", "fdaa46c6cf16ac5fde7f78faa08835ce426cb8fb0db36dc241d88e09cdbbfe2fc963ddb7707fec20f241888e185be3bda368f926d7613083f8f5961fb4024ad6" },
                { "uk", "e7b383f0085592266ee541dcb8b7d5047dca256dfd74c8e7a703deb9d8a19432b950dbc5212cf5050d0bbba0dc15880d7d89f2ee72ae39886a03345e42829432" },
                { "ur", "1f09d5f87c6443ebddcc5a1c4672904da508332e6a5974236689ca7bf098f7222b11d42eb0e9b12b828b2fc97ddb59d58dc504a599e40d298700a103be4866e8" },
                { "uz", "f0ee8cf288a997fef4d61d335e7a1e5f7fde9742ccb4c596c680afc96d990cc30a5d2ac5d9fc94dec2d16e90c4879f14d3d720c5a1294d4f40e328982d38c1c2" },
                { "vi", "286207b2f3fe6b5c9cceecb9c9607de4766d36ee229c11a9d66f3ee3e4a6c54b82fc5d29e57501f3169b7bbb21666163b4fe4f39dcc737a24698b04e7f42debe" },
                { "xh", "401ec24c18323d01eae6c1b6c44bbe3aa801ef3bfd7fc1926e872764399b5a911cbeca3a6206993f92ac4a8897b53516c562109dc2fd66a660bb140cb16105e8" },
                { "zh-CN", "3ec8e298569be718e9fe00663ffa61147ca565a90e02026772eb5984444dcdf8b4a01ff75ec53ebb82be4364b50a8c6bfb6fcbb2a3eccde254fecfcdb70c947d" },
                { "zh-TW", "6a3ad94983360742ff526575ada1edcc0bab3062e5058cfd8b1563356fe4f31b03127f7d1ac924b25c8cf15e2be374970247debaffa41a5049a1bc5a56717652" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "0c928ed4d7a16c469c0c47dc63878296da92af9b13ef3df821e166949fc50155e39ba6f44f360e014d861453abbca9cb2759428cf44452ca2616d12080718ac2" },
                { "af", "bf30802c367ccdf2ef4ed81eda79cd4d6ea6ec19fabb60d14ab66cbfc67cf567d0ba577c14f59aba8e1396fbbe0e0365b13932a950d2ecea04633de366fb767e" },
                { "an", "84918cd9d01f22ee19b1a6087c9c705f4aa6f306577ae86171f041846bb82eefb52c1326b2382335f6335e97ee209975fe9c451ffe23910b705e67ae45696824" },
                { "ar", "f901542c1369b02b5d2de3709422d386b403d3e85e87a2dd3c7c65685cc7314e92ce32acf6271219d8f6ea7e977eb72ee70a133d2582098f32621186f60c1b0c" },
                { "ast", "966a8d94e48b86df4e045c0ab815a5ae52f8b2ac423149c261743044750978b4965dc172b9d372df073ffec67d0df276464341c7f2ed7009ecb4e637a730a10d" },
                { "az", "6cdd5891cd2a474caa4723d1599f19d03af409cad5043ebad246412bae21d1250d2db2c671bbe8fcfdf9f20e432885eee093c4785d54887c24686d7c945d15a8" },
                { "be", "5d2853e47008d839d769b4066855a3a6178370f0edcb65e243083db67bdbe70f17ba25229156febcdef8d04624bf9eb31607094509ed61ed8c70341d2096bbed" },
                { "bg", "20eb07f7cb23865c7960866e999d9e69954257d9b0e0c1e503f94d0517fbfa9cbfe809818fc3ae020b88fcda661b8a1e52642f5b559d28d7bb2190c2bcb85576" },
                { "bn", "e0badf40e709219aef8ee9a31256103f1bb0238a7822678cf45322b4a4f3880e62d0c39dd01a751b95872e7acf5e409d365642d70c096fa58b09888e403278d5" },
                { "br", "d2b7b88c58e2e3257473449bb58d37472f4f71df6528d5afdf01abd3585eb6759d9980c4a2e99e07bf652bef75bec8ae215d67e298e9cbc93a029bc6903ccc40" },
                { "bs", "716b2f9af40d9229599e241383b11c0779eaf2b67c89cb87d6b25a04b2cd11abf744b65d204fcf03c838d89966ad47503097345f45d84c522a37709dda6d1610" },
                { "ca", "5cd774dbd3edcdd4bf9f1f03557bcf19cd701668ed153e1de233e0c31e7bf5c323e988307a71a3956edeeee6843fa797132b192575ebf6c59bc2292add2e420a" },
                { "cak", "fa9c9df493bb0dcf61751a5735e3bddbceb0b5f4bd4b8994ff8758dc40835e039640feebf1c2d01594f7a1f9bd9201862f50137dc0175e9090d690410a62bdd2" },
                { "cs", "71a2d4d058cbdcf4af68a1b4a382b8aff4d7455a7712bf623c90280eb448f4e2867525b6702b37479ab2064b16e26153d810d7eb85f050d5081363d04a1b639e" },
                { "cy", "99489c9c6cb981108681dde2dfa40f58de20dddfc1ef69632d524ed70930dbcce1a3f677836bfcaebf2e0e419638b5cbdfbc3838b96c22e090c0c4c333302918" },
                { "da", "1c5684e24cd98d9e8251d5ba2fc2c63a689b2d45baadb8224c97888f5292dee975a944fbf243eeb8cfb3e67b102e80c677a906c7edb6ab11cf8487e97c518101" },
                { "de", "8bb0b095077eca93a2d0963c877e41626573eacbaa6d299da7a6fb74875835b63e1033be137679ece3a04829b0002e9728c5cddf3835b10931657eb90f5960d9" },
                { "dsb", "e9ecb02bbda6c79288dc9598c8b1e7ce5830bae36004655d5f90a186ed5892fe5243289d266cb8145676631da29af397d0cdb04368a451f62d4e76566d29a1c8" },
                { "el", "9b765b557c7f2e2a2a958ae87c5d0fca05e869e1f09674afc8f9de411f39fff27ea09bafe07a7cac3efa5c1bd3b486afdd67aac29cf136567219f5d9c2ef7b01" },
                { "en-CA", "66010b6594982daeac9b43e99d95f2c08baf4bc2983b77329aa0b9ca956fa3d9e5cf3068084c2855acf5a5b662673952f0a6486e9ffb061c83ff2c1bfe44b1ee" },
                { "en-GB", "87109358671126ba522be6be012abfeb0b17891b3417f473c7c7d3a4a0533b2948b925390263929c7a7a2fddbdcb9306a9eb62a0a065fa34d9591e9590363e26" },
                { "en-US", "854da727cc33ef09f38988f1cf3df38e4da0e8038d89efad6c6c686776b4a6ce68caff17316386c96dcb4f6477c0f3fa79951bccfe36440c4ec530f2080467fa" },
                { "eo", "1fbec8b1f31d77f598ec55056a48a4f8e6f570e5282af06163cdad33f310fe085461e0ab518ff8e2dfbfbeee99ce7304e86f67481f7afa4a4e310cb6271db75a" },
                { "es-AR", "011ed7442980df8703252ff5ccbb00800363708e002fa103c61245cc85207904139e2f0430aa559df01d554e568ffa3360fb509e09152ef52a953600df061e6c" },
                { "es-CL", "8703f1cdd58d58db7a361410ef8d154da1decebe27b85ad22a256131c01b2392d3ca9f71dfaf63b72584941ae4fb58ad3d420b1cf50da36c3eb7634aa4db9a2d" },
                { "es-ES", "bd7f7f4087516de96f90e64de70bca70ad36ff086f8e9d2bb2895a26cb56dfd19b8b144bb664a036f160db77fc820349637acb11b6088294a0faa94baed75533" },
                { "es-MX", "1e1c6ce76b985669172746c8de469f82c0be173b7f5271a79689d0e8300010fa9c855047ac948a2990aeb87a072aee01da40a23488a7558136d112e7ca2c08b8" },
                { "et", "66628afb9b367107d1a9cb883d3a2f73485eec8072cc35df9396ed0edf0179d6646d4dd120e5f84bfa567a13a9ec08284a41843e9343ae91060f42dea513f89f" },
                { "eu", "3a4d8e85c7703c5af3b013e65b76066f5d56e29a3743c4768973d779cc2266584b1885da161a3989ce8501692f5a667809a12037e17c4ad3a7a40c1db8235f50" },
                { "fa", "3d46b852a4d4d1a3bedee33a7cf8e9b3336be47e7850e0b58a58b741222d2f72de7570189d6a873ca59a7abf8ce60b160d79913fa6a5e578f9309a93e7a9e11b" },
                { "ff", "e9f7ca89dddc0dd1ef7b8fe4d223d47ea45c15c7193988cb9dc9a40116c49062f4dc93713bb4f47133127c9b91e9d5049c5366465cc6edcc1fb106351c030422" },
                { "fi", "7feafb943e8c56d6bf20761429bec802df087dd9744b6ca12b69892ca4191f89259f7596cf8c5fedab098ee63a0886d8011819fc4c4bcb07f09ca6996d782f3e" },
                { "fr", "6fcc679482770b11bc56728fa941d6e8db28805d1b4df315fe9f882322f1b736f185a240d63edeacb6fb6348455f0793e3c238b78cdcbc8040d5cb7ea394faff" },
                { "fur", "24a1f94dd9f125f40fc3df1c7ff47fd5ffc10d51fa02377f7a64d94f2a0d0814d2e8d9a356d7863da0691dac0950aba2c568f8f93a3e9af2716122e63baf822d" },
                { "fy-NL", "12b3e04dc74654ec1ee59f5f230d12e328096790f5df648d3d03b7761c95e7c8d17f67611801d5e342bf0991552240463212c271f456937405d1af65f0315b9d" },
                { "ga-IE", "1368909dd398cfe178be55e3ff7fb49cacd913cb8d3c3fb2e8d1443918ac2efbd44603d8bcc3b95eaeb6ad2ecffe94105e1f0afc47291605050a12218b774493" },
                { "gd", "deebeafe79fa8eb8b8b27fbc6065eeef5c6ff2fb136441a944868cbca11f0c86f9a3f5516d5058ff0e2300186d3b7ab94fac777077c0930289ef9acd6bf68812" },
                { "gl", "91e6fa794f7f84165caf5dd3af9e195057ce861c8b787a3a0ff9a7fe024d2ba207c71308fc3badf6704557c9f3fae98735708dec9b71f85b03455b66cbf20cf0" },
                { "gn", "e4a821912c4c93b0cd70767673bcc6a92e4a049261c00977b9eb22cbfaf6b6b19478fbeb7fe9e1b37beefb07f96b14b35eda4aaa61daa03aac73737269ac1876" },
                { "gu-IN", "bf45e0dfee36a02b4748a520899a9328b48eca5bdceb1274ddbf83d2747771ed7b9f8c10aa43d1feba6bcf1bc75b1283209c9faf073bcff9639a9c287a4552ec" },
                { "he", "898b3abdab39c6180f68c605fbc917e761390f70c91c9ba6b076f5a3e4f91f59507ff02e4275a49fbfca7c0fe3cc3176fd811d66d578c95e753074d3ce06eca3" },
                { "hi-IN", "558c1e4bb941c5198ca61534103aa81badd857fb34f6216855fdb24533a9bf9035c6e23e6117011b201add728b351462c7bfaa381647870112cc3ca84839e34f" },
                { "hr", "03290b834527ebafa4b9fb03a309c7fb420ee95ee12d07c9e57b98f40a38196b92505188313f5c15926d8a7a4ef6746ffe48340ab402eee62b38c78decee4997" },
                { "hsb", "e4105e7a2b8af5abb0f70469aa8bada5700c7cdff05bfbaf9d9530e17eeb07a81b48db20c9df19dde267873334fbd26f85ca1a6afbfb1b0a5471120b6829a39d" },
                { "hu", "909da989fc3e60bdc68e332e10c746181aa13ee03099df9802cbd32689695664bfd1364286113d72dc89b7048ec53a26181128755939fce72c06c36fd102d5b9" },
                { "hy-AM", "cc44a7a8b3442f97648faed895b646e821ad1c0dafd427405f4c384a75df750d25d792e2b854ae04c2c4310e8e67bc50287ec0c92ac1d31dcbdb2d66fce0ebba" },
                { "ia", "676e4964b37457a0f1cbf123ae35aa7df6c39ec33d1f915a9eadd74bd28b293223d607a7f232a5022c341ea0d6633bcac295970c423c5530848ccf2a7cf5e985" },
                { "id", "756e8786f7b0574f2b41b920ffd483ce8c4d2876c86fb65c0ea7e6111f4d00f3232199b062dc1f6597a2271bce0bce3aa071813881e6b224c2a930ff77ff031a" },
                { "is", "92ea53763007ce7c7d895f3da7e346c77d98b6538489fd9ebf55200d7c8f3593524e5a7617bf45e029ddf8eadd0ba6c486140592eb796bee4072330592d3c591" },
                { "it", "6b1f3acfe6f01122687f9cfc69d506a302a5bddb996151c5977c2eea23eebda9552a4597defb50893be5a03b9f139f46e2cd2aa53628e5a921caf9ebd2993d98" },
                { "ja", "8187aa4413d987a8d5710f3725298a1f45215476e1888a28bf67fef9521a0e660667eb03469019627f342c6e77a213a137b87d4fce50fe8c6e45c59d37c3976e" },
                { "ka", "cbed3f5b71aeb52b1ae006893d094bfea987cb3886956037ad0b48776372e8962a2cbd01f338b8bfe540f44641fa3cb23dafd8df1620fd0f1d36502a5eb8f7c5" },
                { "kab", "b20acd4ee79a92354cfa2083f9089bb018c2c86efac26df965afb3bc4964569c6f09e45f3d86a07beb25403c402c42ef0ce3c796c36947497f3d03b280b21700" },
                { "kk", "292d2d4341b94d89d50287eb81773f0b39a325ba8d8e446c30bb1ba5bcb4e48ffae271318858269d257cd58bfd7430454c9a2183d2e9557713865a5f85181643" },
                { "km", "df0565899bcecb3a0aa0e3a8c064433b44095d95ed516a62c910eac72575eca7b144327c7298ddab65d7489d4b0aac59ddd7d48594a9f841af0abddd5d2f5dc4" },
                { "kn", "796f274066d0d10b0691518b0acb7e541daef538a8741c59691571b0c19d12a6e7ca1d6857ce101353369b4b8af6a159f594febee5324881078e94243ed52c72" },
                { "ko", "9ca63712451c2589a8f4061cea01ab4cbdbb49738f4c20a14dfb4c8b2fa6604db4c55703bf8bcdcafe4427928eaac38c7b23bffa1fafe341e8c32848a2971a6c" },
                { "lij", "5b86bc28a796b711fc83161bb1adef2eddbeb319b7c0dcee9c258b97cf34b382a5d70b84b35e42df1a5a898acabd3f2dc850646b316ec44b24c1ce2784e8f30c" },
                { "lt", "0100a13cc4491b95832074ca6f9b250f5ef7634b7193ac9f3deb728dce191024dd06ca8b12791f36fedfd0645339927eb011761d17cdc7c086d167c1a5f69a53" },
                { "lv", "7c1280817b77be4b3cbac7188102cb14516973ef910079b919596a6cd8a50de94beb0a064a654753da3ba01f5dd07a421d743fd710bd442311a2b6461556cd69" },
                { "mk", "eccfda5c6d244a55fdf87c2b3d4025bbd6fb85b535d18992b579f1e833a5dd7d2097b82eadda267d416667cb3e1ad0ce659e96eb3acba58bf4fb7bc258ad9887" },
                { "mr", "df7cf83ebb106c21cf8d8559796e1f0e207bd0fa2474e18f47a5190ad276c00167d3be141e8497f8d6cfdcbf6191864e62475ac51ec6476b11e1e14213b30f40" },
                { "ms", "f67a876767e21f446f805ffe5f2bd97f04251ee5124d910a4cc09e947120b526a643c47e99f53c2d46cfb13bb1dc8bee67b7361d7fd5844050953c09f121c87f" },
                { "my", "48406308f64d988440a193819d4c2912d524dbfd1403061e65089b5fa81e17f710e248406854d2928c001c787a5fe8e4bca75c76aa536998a131df4b4fd8f315" },
                { "nb-NO", "3cd0ba00af1e3c90d8394684c917b4fcfdffd55cf72e468070aa357060ea54f8b9191d072f57276e9a5858c283726d58f069ccd90ea7f52cabd3a43a7b3be15a" },
                { "ne-NP", "8d508a525e6caa73544b06fc00f745fc7fa7f8a815a572b529a7df70f68b18eeb1d5de862467877ef97aefdc4608108094630902ea9ed1f8158835b2777ec91a" },
                { "nl", "bc313aeed64bc97efa73bffd86baee14e0ab9e65ee57c0b0ae988d4a0f3de1cbc66f606edf5665b6a1ee43de7a2f487a6ae7cbcf97a11062852df3d1604f9c64" },
                { "nn-NO", "52551996539c4d9ac1408b765d1de4378967058dc6f0b3ba09f7e347de6e0cb1094040344ef6dd14bfc4be78f42c19fa264668c7d0ba43fa97ac325b25ad5a29" },
                { "oc", "9e649b6f9de344f98d7564ec840c410866ba929d411d9cf3d75f02b9efdb9aa988d769760fb729e564aa936fbe3c17bcb0ed633c7f29c8ae8b46bce426846b26" },
                { "pa-IN", "468eaf8e19948e3ccf1cc675f0950cdcfe5ddb717e226d8425a9b7fd30e989b6c986b0cb911cea323c2feffe68ce22582adcb24b7fa353d30b8f883f99a39140" },
                { "pl", "655828ad120d76e29d40174028b35b73990b8cacf55cb36e6262e8bf31906d3c029102f4a9f2a46116569ae382b21781a5accb49a5e584cdaf858509c36518f2" },
                { "pt-BR", "18a229769e6a99098dc6b3fc640f07cf16a847ffd438963de0ff6cfa37106ce35699e5ddd1c8f5f7d585c9159de6c0676b69c2fe33b52d8f38064ebccf712979" },
                { "pt-PT", "45f2d318f4fd7fb09d57d3846a387dab28687c68db74cfff9e4d694215015f83fda566237bb562f584e872d570b35f84bb86eb680a4f08103cef44904aac1231" },
                { "rm", "a06f5d290d1cd49f75737d96efd9938179094cc6679d30c017665406fa05cf2e1a06fd10268f262e52193f8808ea95614552717ed572da2889ba10e051b0644e" },
                { "ro", "4402b6bc89a1d236ea445743fe50816bd9966b70b3c6959f7559298222023750a0783a1955cd1030dacc7d0f55bdfb84969f1a198d64cf825320853794382c34" },
                { "ru", "d64ab0981e5556ae6e053eabec7d8ad20477a3640d054d1b64124b1b961cd3d71790eec9ee7aec5c8fa08b8e52b95a57363ab42c3adaf851d8cf81fcd0317f00" },
                { "sat", "b2a55d144e0add001b50be74c6f8c890de9792e1c039e8bb08894db8f96a7a8960057719f01fe504838a72fc6a1d0ad36c1eb26bc2136a2a9c824f0b98ea0226" },
                { "sc", "c62584d6fa9d6370cadb7664d506c33fa72abb8cdf52ab14a618910c5e2d16d0d0109d82588f09bd7a5c18f0d987e4dfa8ccd4dea9bab61a4e1efc11afe1d163" },
                { "sco", "16381b5d32b411bcdf80a2f0e112d5b59397b7047585718970c4a067e8376f2bf5d177acb5a45d3476dc61256f625cf1bf2f1036eccf79a38153cbde789ee7fa" },
                { "si", "e922d9a5d133fbe3092aa6dec8b3094c372c97221f62f50d58fc2b3213b22a743a1e074cad81c5603c6cca614270f1402cbec482e4eef4d2b9345e74fa9d00ef" },
                { "sk", "7f7fd6a189457ad22c08684ffe26c8b81d353988bb8105e7d2e0e16596547274e7bc75c212b1e18a17806b9525ab4f57db56f89c0d69b6b14f5de368e64f668b" },
                { "skr", "6b3d1511b7c510af08e91068b5d15847fe1d1606d7ee9e2312a39dfa2f1987f640d2b0f8d52fe59d2c5823d4ad0b57ee66994e911aaf0ed3b08be6754f934df0" },
                { "sl", "4a72de0cac15785fe5d2a09b640ac834adbc9299ac2f7a6cccfb212ff402745ed27668de4ba3fc5661a0c845eb63b2c7bca06bc56fea3573892114cf375fbcc7" },
                { "son", "447e6b14882779eb594d7909adb0ad45c4fba98b6311e76eee356bbbf1b4161b63d324e66da5bf8c8ea3957f7558adf589e39b29288a379ff57241d354a65749" },
                { "sq", "6a59e619808867a1286b927af2163b280531a24d9758ef0d72a81026ec7331f0151cbdb0ffa8101f42281b76ac7f350c8dec358681f38d3725bb62cb7b278d5e" },
                { "sr", "0f0605d7a2b3ff8c564588cc3b2afd80d707d5bbd07fcb3e1f36a3e080b06a1dd5704ce7190d6eba6ca23ad3bf8fb4e68eda76e53446c4411df490cd23dbdbd0" },
                { "sv-SE", "d941803c451af563fd4f36a10671e46aa1cd70fdb4d63a69a93d13aa52325c59f6e30b267299e27525a0a4ce2b14fbb6c9bf901f9b1cde2dce8f77d86ac68bfe" },
                { "szl", "c35499693acf7a33c299a1f28120434b1681940ec180429b11d50e23903b6db7c10301449dc52a95ba5bc0e6f90fded17bff54a9a765c4ab2d0761b7da603439" },
                { "ta", "96d43c89054ff368150d0886a7a7eef2395290bcf048b795a4c5b4da15ae54a98cc6cc4acd0b986d7844e714dc43a194c2ed400adc7f9d9080d8839a5d965505" },
                { "te", "a0952b8fdf879282c57dc825b609409adcf423a0c0b777a1937182e741fc280cb9e0df4b9dc1086270b7f33c2103087e84ad46caa2a0a1bf64c4f3da32556bac" },
                { "tg", "86ce9b5e40827a65db836dd412f20a8533463fcc3ed933a740977f499043aa30a3f719299b5ec71204edefe5a115f28071efbc4f98937cf11707a0e764c36b32" },
                { "th", "44d24e184b5e5ade670f67d9d8cbbe7783f4c679e1218e731c0ec75a0a1d1f794710c7b86121b35d4b95c5f0fe66db3bba3d39a6c84d730946ab0dc55bed3ef2" },
                { "tl", "4de9296791358baa0e735352c6d6af808ddedb38f6b5a22c82bcab235904b7ee2184dca7650fb2f3c6ecff7f86400426b5d86796cd798a7f3783e33b42ea1595" },
                { "tr", "b033902ad6a8d360f72d4fdf2f2ec22c614505ae84999070bafe99c8f5a44624c8047d8ace570b783807a27d29baf843f599254221634abb48fd27dacd7e72a3" },
                { "trs", "96aa94e298e02d1c3ca5eaa32af44cf10d6465b6e51fa4140ffcbd197e9b7a3f44c7517b6986b2ce86d45aab4c069f7dd4bf9e79935c087e235a5ab0dbdb466f" },
                { "uk", "fa4dacb869b5a7445d7b718dcdca6c058effda36e9828a8349d7278e1d468b275163e10a4e505d80897bb4462ad169265d22020c3fa6d416a223169d5220fa83" },
                { "ur", "6542efd6dcce590e21dea4270e70c710a9cb32aa1b82dd1f561baa9397a511a644710695c26e78900ad4118a15421cabe23d7c79a61d115505a2c86f56a9f9e9" },
                { "uz", "46dbd4b0250aa21d70c3c60b048af01a07e509c8f4ed375efb322c4bedd9cf61c321148b84eeec62bf8edc8f691d864c3299f498ead9dfb9ad482ee96f955527" },
                { "vi", "3a63224679de8636eeace3626c6656745b12b87ddfa70806a6e7ffa3d3f01e0e07c2e9bafb2e2fb51940f58d09f466d1920ba52f281dc1d8e20783435f6caa0a" },
                { "xh", "59535175908d4f158a448d1dc9547d497eb6139bb9fbd93653b9cc6e7b7ae63ed37ad0e4460ae7ab89178a4f3fb6b136170507d165e9de14ffc0a48fcc56ad1d" },
                { "zh-CN", "b1730779834adaa9b4df6e133db0a203590a60da1be87eefe41a3ecbcec15a0c61861063423c0c325e4de7fd6fd8c6be8827257b776d6003d5d9047257b74567" },
                { "zh-TW", "965ae2ad9783933ae1498e7fa98a8d767eb221603db42d3bc9984d4b1f763cecaa4786cfdab962c41a4d75f984ece3fb0e8bd33bbcff5262622d1ef622d30841" }
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
            return ["firefox-aurora", "firefox-aurora-" + languageCode.ToLower()];
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
                if (cs64 != null && cs32 != null
                    && cs32.TryGetValue(languageCode, out string hash32)
                    && cs64.TryGetValue(languageCode, out string hash64))
                {
                    return [hash32, hash64];
                }
            }
            var sums = new List<string>(2);
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
            return [.. sums];
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
                    cs32 = [];
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
                    cs64 = [];
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
            return [];
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
