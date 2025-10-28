﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/144.0.2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "5418b7443cca59df7e6ff647d1680f93bbc06e5713ec23ad5988da265a32eb06550e70b6ce0ad7bbbcef2747bcc582623cf642a1e0bbf4077e26758d2aafd19e" },
                { "af", "b1614073f709f851eafee6034f81ac8b620e31a8b068018f403b7ba6a28d1bc06c580f74b25c51f46f3abafb36722c885625fb91e999e870fcc5967e9806cf8f" },
                { "an", "2de2dc8057591a077d6c97413771e21ab708507c2973f05897823fdd700796cce8c2f8d0bd013f940f0b93642623c947b0f8b566ac4017d25a929583312d9082" },
                { "ar", "68e495e6d2d15705fb367976eef5e5b70892e830c30c046c3a0b1b61823c861ec6423d97d5eda8a43630d40f61ddecfabddbe927ae8770a112298bef16b0ff68" },
                { "ast", "acef70fdf31a613dd359c472edd8186f59f19f887d1ec1bca1a2602c293e70fdec911aeb6f97754d0abfcbc219df7eb59093d821981a5b90b7b0992002722713" },
                { "az", "ff75f3920487ca751c50ef04fde5fda1a7349a9247672ac7a2123ab4a03e32faa769bb8ad51d9e3add35c31759819aaf6e3e2b6df3b8834e4070da67cb5f6bcd" },
                { "be", "5b6fb23fca0326f511fd2c6f0f67e6439903ef61a439075ea349fb452ee9cb4badf059d279ff6902c9dbe07cf1781ca6d75c26ce23b3f2c164a7c04341748246" },
                { "bg", "9ded719f58bee9c12bd47d3561b8faf5ca3e5702bf84a81d52c4d0285822465f944f7df82a741dab5e244f5670f21f6de0dfb1a489feaa2e230b8c2028980dbd" },
                { "bn", "7321cc9d58cf649c1236bcca070e43d985861d23cbb17c05cfb6ac572eb3147201d298e417cab327cd37c0b281561a5b32075fb06068a11b58dccecaedbb0b26" },
                { "br", "fff51c306e70e8d74b6d67c5bdb17a28f5dff738e606bbcdbda39b4450ecddd29230beb12a7470d92f462a3b9f18c6fcadf4aae52b012e600ab1071a08c5bbbd" },
                { "bs", "f77e36fb953b0aba93dca18359f43a3a7ab1168746993c127006b65ee7ae811c40a83231b615e2d510848a46175e40945de1f78768f0af8e90d0d33551c79e76" },
                { "ca", "4bd3547e931008672cecc951e3fe24bb354d158f9a0f946f95e6cd158c72e325abe4f78f5a6bfafe4a4ac641ea0e9acbe0f05821400f828e781729d385822898" },
                { "cak", "f1864cb8b6c9204c7895bd7fe2048dfc8b3190299cbd1d4110e2a7acbde5cb5aaedda13716b3c6ea35d5e7e9d5a298e6ca6e5d0aac5528fb998471208eab1ad9" },
                { "cs", "fd5e967af51239a4e00c0907a7d0152a23b4cd47968f39bb78a227cba0199587cbf45947becc7b3f1ad473d5759eef92a50cff611fffc56c82058d3477274abe" },
                { "cy", "ee7a2643dbad9631bad82a4eed13b135ce19eb36297fc335e53be27272bc074eeb7b41700fb3cddec363678f29e6b6581542e49dbd5ef71c78c50d4feefc25bc" },
                { "da", "f8963644ab577213885bf6ce28800ed09f136d770080ccd226774cdcd663ecf14515ae7b144a4f752921d63c7f4f97976212bbd676e82fd309770cb1d763ef56" },
                { "de", "e907ffa047474021aa663cec9a7c4d4ef853c02de36c544950280c41febccb61a5a8c804d81a7f52d143ee4d59eabc0f1449253fa6cf3a1b090fc731b9cf60ba" },
                { "dsb", "a54ad93cb9a0b56fbc4801c325e90a1ba5e5d492f52ec5c97cbdb80e1cceee20e35286dad8175405b9687ba75355fb68c16805c4468905d6b3930872a5fe5760" },
                { "el", "656731d4eeedf2cfa14cb30a142afdd59d1ef5995cf5521675dced6dbd94471fb7bf52ec4a5acbf06dc5778af5eaf1297f9b1898b1c2cb4eb9e1cf2d7183519a" },
                { "en-CA", "b4ebd71ff606d2daca7dc31e4a6bc1793e491e868b68c433cfc0d1db5fc79fdbf365fddd43c5de71a206b6433f0cab93bdb19c4b04536dc226a8d7be8bbbefa0" },
                { "en-GB", "dec92bb4c48e6a9409dea900ecc722a94143540e8afac9a650eb77acc86f918ecf84a85ee7e5432b1da59645b4037993c4de388a32aa70530d3aee81b4ff8440" },
                { "en-US", "5e0fdcd49f8f6fd1a03cc6abebbc6ca517e8e1a50f94bab1c85f63dc4013eddcc06275cacecce60aed5a43a5dc9becb0d5d59c0c3a331ef430407ffd04ce0d2e" },
                { "eo", "f22c4b51779defef8fcc0e40670656cd60b728d6c6030f9eba3da3abcf8bbb38c05a5abc89db39b6c7f12691baa9c6aae6d07712627f8236b04b9201c20b3da8" },
                { "es-AR", "02996517032b227367ef6ac6e3a081c57f9ad61163bf73ea1eab640bc445aa09ba0aee96f4c191397d5b193654ecac739b3ae1a2ef7db34e75cf080038dfa6d0" },
                { "es-CL", "8f949012f06570d7686317ee305f59b76f14f2ac2e6381b5ce3d3740c8201136a8ad68a8baf172f4d33cdde999cb30ec7180fafaa7a39adf1ce188d3be29e4a9" },
                { "es-ES", "2d3325472dba9bfbf4e381247d56151d6c2e77388dded1b4d8313fa210d3e877231dd81fb857df4c592457c914ac658da65c66c2f1ed21cdf74d43ab5ad6f10d" },
                { "es-MX", "9a1aa5a5eaeeed9930b97d700db049083e881fe072339db3c67e6c51a4e6f8a6abbe6b5a1d93d14d457b41cbee96c82bd0e44e2da2f6318b5b3192aa8893ade9" },
                { "et", "3dad02f1e618a2a48280549815f9887fbc961d884b53332889872cc79f658c9ae2216937ea78f3246cb1809db2bbdf03c95e0dddb62f56448993a725743c93dd" },
                { "eu", "625140ed7afe023997356874e43d2af3127e5dc29c44ffc087a54aa6686b12b183e78c2a7f8c33588b933e192931677c3fcf19ff134b0605a25f3cd4d8daf2b7" },
                { "fa", "6b24b75c828e56f9f6387ca9a7487fd4024abb3a715872989bd7e1902203385f8b0d2bf23f09217c2d014645bc3c59e8c20dd15ec52e82c0b5ffe8dceff567c7" },
                { "ff", "b9b282e4e66907e182ea4ff65f19758221652a0c2ab58eecb1113e38d4a197fa94d4760171ac2327afe5ab653171abf0eb0c209873ee3b46cf6b9808b2ff33a1" },
                { "fi", "36f35f618f27a82a8f3be645a503cbe03239c4dcdb5e7ab1e23bc65a3877b7c12f38506735493a410085be4facd22638c11632331edb867855deb06df55876d7" },
                { "fr", "e5e5dcdfb1709d487c4d520eac6835226febdea11c07f8b7fba9f0b739c1a38f2b5fb8476da47af1744b90b64da284f8226d9b0584b166fe2fd0238b0a2abb8a" },
                { "fur", "f61f590696893c317e990f39c5959b8ecfbf2ca887bba2f2ce5722f6e4d5e01f6f7329632aff32686a147b9b8ab6fd6caa1f1b066e86d3f6c55c907e22d5db3c" },
                { "fy-NL", "258520c6a9989c837544c15ac19d705090de11aca880f20394f5b527e7668866d3edc9e37145e2db8d467d7ecc0e6245b911b9fc5066683abbf797fea6f7b74c" },
                { "ga-IE", "7c00bec4d8d985aaac3f196091f04b5baf2a6197fd663d2f9b67931b1b7785dd15671a7cc425e80588beaeef162bcf11b3e154f1aa30c6a4541b49134310e2e9" },
                { "gd", "141513b9c5c47d4d7cb090a623393aab0a2ad7ed19d1979eb2e4ee794f25335c94d79812cd696c63a9034462dba21e9741555e918f1a207dd24e5d93e91377d0" },
                { "gl", "075b609fa8550f0f37412ac91a49c97684d2034f4ac9b23ef6875d558d9e4e3b359ecd82657f4e442d0381c72d9132025ea85fecb1ee0ae53541fa6cac291a0b" },
                { "gn", "b78a5bd21e38de62a72ce165f442427250b1abfffe53691b89f3748e8f0c39b6108f10772d0ad0fe6bb9022c447fb904bb900c48b1710a8f0740ef1c5f0cbcc4" },
                { "gu-IN", "3611f7c52e673cab19ce3a00d6adbda4283d6e9e3e0e080022c1bff12a3110a864031e94566a79338f275023dbc06e87b915697d1ffc8b922e8b85be276a360f" },
                { "he", "923cb111827dbb8ce1d8a0326c81886f731cd3ddd1316030f2726b83356dfeab229f5c9e4ce1ea4b4559c4ab7aa5c0c3a3de6072cfad35e03332e53bc1f49a95" },
                { "hi-IN", "d556624414faf78dc515cd31d3dd24f904f38917123e9b9a9b9efb542fd9cb946749b7694b7ed716c67ec42d5426075196146feb6306466089e9b155f2c0b42f" },
                { "hr", "852238cfc5a3cbb7a595bfc08986e11fd88df1b46dbd095608398088dbc120da05c485672b2a2f114feb26c19746fd4f0963ff17fb4dac8356500b208c3d412f" },
                { "hsb", "77a7de9f7a1aa4d84505a09176f60e664d6f31b9fee2be3d910c4f0a656339582ec6ed089c44792e7efa8fdf5ec2aaa7831ce922374004da1474636ef23f8500" },
                { "hu", "0924b33a577ffb4189ddb7ff5b900f7bd5664ba7e305c03b039850ceb4e82c40ccd9f517020b61cbef0ba36a96e0b63343cf76eaa9872d3fd8b6167f72df3021" },
                { "hy-AM", "052972c304a26bbac46c1e5a966ba104c992ae2cdc6d85c998a2f593e34ac76a1a4baac3efd7a6618429148185417e5a5de8c4624677ea8fecf2e0de073fb36e" },
                { "ia", "bf03784e766b29afcc906f5e7d2bdc841146cf60bb5341997ace21cb8b6fdc14b03551327844745e4cfe85ffaa62b10d0c72cd9a5297ba7851c5745dbb4b5d15" },
                { "id", "3f2a9f8cfae8d2a3de641b6e38167c273e3a4f37abaf3c5d58dc91b3338ff32b2560e1dffce1c62b6dd6e378636e32188956d6637fb7c42e3b3d38b0eb40275f" },
                { "is", "bb97e425bf2fc9f9a7f08242d0d4d4144e185c5e9b342b20ac5caed1d7ef791d10f69652e29870248582a005dbb69b8c6701569635180bc04333d003956e253b" },
                { "it", "efe9711b93fa626b563799ec4a0fa4585d28a26cb351fc97fe6dfa4761b06a743d1d44e4317062afc8790906550fac4ac26102083c3f5f91a7f76d7fdc28b5c1" },
                { "ja", "81b394949dcc89aff116c05d17a2a4a54247f589fd5e9f4ecd4d7f94fc1439a6fb83a6492831621524df5d1f8c01e4e89e20bac77b4a1ec050677e3f89f09b24" },
                { "ka", "ef57b50f9c4fddeb4eba358e738d6067cc10bf1132fd7f628f4a7924951c1af092aba4777ba699153612987afce67cca167a6bd5d9cfdd8ac96ee9b836cea377" },
                { "kab", "a8e54d4472dcda9a6ba60c85d0cda587de72030c0391623fadf9a5db9b5474e4ccce8ed0330000c555b4159b918d780bb82c5ec2a6f351c7697df97f7b68e424" },
                { "kk", "e8f407f5222eadb7135e05c11abd6f4319027fde345daee4d430734acdea1580fe1b7f384eeaf9b5ab3f5bf73ee0057fe53d18d9083502dfaf9d334392f1d92c" },
                { "km", "8911a1a44eb46d443497c2a47d6d40617a0db696addd2c848fc1a6c98d8cc5505c0ea155f76a8e8104e826fd068ace6fc3aea2db2ac7dcbe5eba43360eb3b321" },
                { "kn", "93fd6351af7a355927ce51738834319f2d897bfe5c7df45b024bbf6270c5d2233990680db06e7eb747705a00671bcafa8aef13c6b33a16ae4045bf4c161e47b6" },
                { "ko", "1c84ccc7c6333e0ca05138c1f61dfa681022717d5a552bdc2ffc2eb40b5157af059b901e9afa0cba2e1981eb05edb145c1408532a420bf72a244b66da63b56e1" },
                { "lij", "04ec7e52b2f280204d4bc01095e11e68f15d82c87872f88e743dec207616106627a297cf1e92a71fb380b5bd5314fa0281ad3bca67f870f0c4dd553633d25f4e" },
                { "lt", "7a5f86f160e589023b807a49fd3bacad00d56d09bdef2592c758a68dcfd0ccba201e407a22ead651e9f6e204a652254a81c1f273ac9f80c0cbffca147ce50cf8" },
                { "lv", "25d6faef2a9264d47b83354fc1826a3f37979cb21b41061d46f58196517824028e28a91df04944a984e5a0fbde0e97d573e01d507f6516a235383063a74e8fbe" },
                { "mk", "dc686a98969ccf382cfa50ff8973dd9bd3eb6b686a4180423ba71fde2fae9a79c030b5cc902e32b2168f0a6de1698db9a146aea45da047e18178fa080802fb1d" },
                { "mr", "bf76c17a4a7504c0e24f1a926b8042e08c67161f05fc53dfb76b38d545fb9c572013de958149d491831ae307cea5b1acc5c777cfe87e74d7c2d8987943f9d6bf" },
                { "ms", "e809c1a4f8890e900b643936c6f1d424848aa38486accb7f10a6cd4f8daa5b6088f07b1db6192dd429ac2fcb2a31297363c3abe3166afa4a9c5f582c82843fe5" },
                { "my", "61200391cdca6d615689e1a84215ef649f06e1a4960cc5ddac34eec46ca615f5efc3327546303e50f91d69b6180ef4d01226df25bc843ba26a9430507eb63690" },
                { "nb-NO", "7d7c88dd0a2d168dbef104348d6516084892785f212275e1ba641b2299f67c88443f83e2f8b00f524a6a7c10062663245f18670db170e5075acbad7c4092fc75" },
                { "ne-NP", "c2786562e95a4083979e763a1273bddaa92d007a0291b7c4277079b4782cd9ffc40bcfed45e3ed838699afdd0da0c3acaf1fff5f4bd1f531b01d67492a57c839" },
                { "nl", "a0b42b9fc0ff226692fc7a6a6be178045be451b2293d5fd55c41512d8e7e8f7b9ce641eea95f260d126526e8b6e157358e411db58b90649a043edf623a9993b9" },
                { "nn-NO", "cf2fb888f4179139d6924210f321dbce742b67e9756d5af4250245ccbe44aadcec4174820b3eab48394c98db3f1db29e1e24640d7016f89b7799fb471e82fd6c" },
                { "oc", "a902a91d5c18368be79c74f2f4bfd761d8abfed677de21222e3b333efab4eb69123dd6af02cae2e984c7fea7462133664ddb6d48c55651d13b7d70ab8a374c2b" },
                { "pa-IN", "2ced9c2d1252ce60d2997362be6adda12fac060d8ca2bdb2f45412f771e76fd5ed7e1b05e24c4042d5bf02bb45883deed35c3d15789ad7eef8dd7490424809eb" },
                { "pl", "8f6998c38c48bda48e08fe622358672de8016d9d6844e083f4e259d84698055ab8afd121d76e89c92dbc44930fe45238c72b2cd23f9d38570275cab36c64e168" },
                { "pt-BR", "d20f71e303e0195dd3e8b50d1e49149a2eb7f2351be9f2cd5b068582f4a9795fd893f72874333c221d198d5f66839b763b24f5a8407959acbe9a1976af8622e8" },
                { "pt-PT", "daed3ea6779f846aae51d9e94d82a5c3f6a8298063e1ca914375fa4119120b7640d09045eafbb42e85d8f46dd7bc5e10d97ef52072e4bc4908e22ff9264e90a2" },
                { "rm", "7a8a5f23ad9f002963c1961a4fbdcbdb38ae0a64ebb1a74b145f9e438fe39045d11107e5fe6000c8db93382db0becb93bc39344cac1e4ac83e5268a05bb003eb" },
                { "ro", "d93029cff1ccd3dcbff4ecc5f5defb5ec1d81f6bda6713a24638f0326f63e3147a20a7b194e8c02b9fcec8dfb0291f3fa0cfb31805136d6f10b3b6c1120b979f" },
                { "ru", "9de1887b947c989e092016b4e759b527553bcc29c116fdfea8e08137fe6092f01c0f2c0450c941910729bd96243368bc9fdb1ede642accb33023d9df51a8c95f" },
                { "sat", "dea3760ed151323a0a939196f9ce4087dff1963c69252dae0bacc64d4baa7ea47ad33f5b53365603f045b2f8691f6c115c077068d3df6141e0b618196c9fd806" },
                { "sc", "5fb09895f7a1c2cb4272e806e41f21f09dd677ae7f92808e1631aae200c6b7e0abb8dae95cebd950fd101625e66a11eb7fd1cd69de329bb584f826a3a7d6849e" },
                { "sco", "4091179c5a8443e9b545fb2f8d636f6579da7811be53635a497b645a9c4c513cef02135d09fbc5870a522886a52c6f0cf192588f3a32970209a0f4c16b24c095" },
                { "si", "1c2aac2228c7ff39a5ae2fcd303c260b6f6696a30a2d82415353fb8c6541752ac0eefbc12b770455ae56bff35b910bcbc347ff58e933b4eeedaae1b0b9fb975c" },
                { "sk", "c810425c468f8d3428ab4817cafcde1f1a18ed6ffba16a74f487b726b81c66278b77bf4f600429079fe16135dda90cb8ef0dcaa6e91ce062498aedc63bc2d6a9" },
                { "skr", "3e22433cb400e41aa94c629a2abb66a36b1b9ded217c4cd9918fd8b75858bc7c533798690f2611c9fcba8e3fc49b25dff7a4f7da8a9be5b9417f905d9c35ec2b" },
                { "sl", "ee7264e4311c6ab881d1461d73d0d87e1f03368f765eda88c1245cccb0237cb8f531728493ac9a182cb34b0b9c2b26a907d688dc63b72f005e75343cc14ea486" },
                { "son", "32c876773d55b409ea6230d68181bb7225fa0867d31459bcd776fcc1d1a674070076bb48826c89b88650077293465635dd2329df3e5bef467682ae4de3beaf22" },
                { "sq", "0b124fc546a58a2608352b4ef8f90bfb2156e948cd0020e0c6f75cb26c1dc7b6214405c0d435827f9a5a3bce50ae0db5e679925da997ca208709143614a31447" },
                { "sr", "bc4f1f5340174ffd5fcb8117f8289a6d6d7ad99d90c0618baac0d73e3b6653ee268700ae965a3b1b237d26936aa7ef12d98439d5999dd2bd23aae9daaf4547cb" },
                { "sv-SE", "a2c525fec81c61a90c30aec03b47245dd2e3a33d3b1abd7d2ada8f9290a728dec809cfdfe2809c9e8a8aafcdb0a9e5d9b5c780c001d2a25f7ff8c2b740b92f2e" },
                { "szl", "8970406019e1afcecc37684ea07eada8ddebad4b0f28570ab4f693735a1631e414ed9017d0c91dbc20328e6d4ccd519a615a554a8f1689d45cef63de12240c3f" },
                { "ta", "894f9b241ab359403ca518bb0f81d5f44911ac156d79627285ef9e55178316f44c12bbf1fb426ec0fb627ef1f48a11f9669d8b59a24d133ffc4b35d46512689b" },
                { "te", "5192af05ad35564fa4583730d47a8f632a73a602f57fcb397aa4d0fe1ff134c98522cc4e7a696fa3185608942578e50772ebdf7f5ca54be7a8de9839a4d011e4" },
                { "tg", "749c09fa8a5ebca361dc735c64bb62fd4e87d041d1af74d2edfe9b030a0e71fa09e468ca9555605988151dead84b8d783c60e93b02f04e3b782a6f410c7f12ca" },
                { "th", "0791a6dc6d74e1b24cb1b5d8fae0f6d3474cc519e703edbaa290f5491c68427b28b067f0b9530560f38473754b016093cf38c515a5da2960b0b81d1ccdb9979b" },
                { "tl", "60637d1704a800327811c4e3abe5a044832ebfb86ba56151e3896610f72912f5999875b394ce04713e42cf5431ae278561c2e9a5b56c5a31854a34c5572ebd66" },
                { "tr", "de2afbcbfd8a1262fff24ac24e9b1a8eaca164219ed7dce3c4b66a96266f71693dd12e55f4b04ce780a93e2fda180b80d94cd7edee7fbd297b447d3f3196c395" },
                { "trs", "81f973ed4ea2ca0cfe680915face5ca90088f50a65554fc7b6b9ed40c99f16164ea15a1dc775ae8fbee5a006badbbef61e43e41feab6b576926df037523e91b0" },
                { "uk", "4a7350361d06b4b55d29b59fd4143db8852e2a528b986989853215f7589df244428be2178d7e0112a60bb59f78190f2f906cc47322ba357abb215f1b7bd7f0df" },
                { "ur", "ec64fff9cd83c76e3dc98cfccab7a1a1e36da66b0190b6d946c5d057f3ef1f4af65238378d8339abaf2383881c51d007c9f6dda804e57696d1335fb0c9133279" },
                { "uz", "2a0023eefa3aa0d2e0a5d2392eaefbf526582ede1c3540403c28875acef7748336697a6cdec840a096eb6c4e6decc0264e0a2707a2738dafb742b51fbc06a730" },
                { "vi", "06c76b1e56e38ab50fb23d89105c996b786d255aa48793c5022b53b1cd429ff4af03c158593537d71cf1200787d26159307feaa99471ee342c567064364a5613" },
                { "xh", "b90f0db176b714bed4c5835e15c6fde2a24b62d69a9376156a0f8bc084275925276416e1ab9afef29089d70360f43d678e295f28d3cdac2365deaa591740653f" },
                { "zh-CN", "0ab7d7321460c8735f4cee72276a9a789ca3c00dbdbb0aa2a0ba6aeb0183714a80bc875ff54db89a805c46f61eb0c31823fd294ceca6fa9551e86623557edbf0" },
                { "zh-TW", "1fdce394e6a4b09a71e2f3b962f9b43534c3eeb3c73a1b8e00353fae969fa0d8d40ab8597ab67f8877f2cc82e33ef98aa0711a387b4294c8ffb7356fbb4382df" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/144.0.2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "33d21b4025c8cb97ae58f4b29b37b6504f18a6ff57f4134640a4d18de0db3d45c4dab183e391c4eae829cd903827064c51d96166552836d386cdd718e96f79a5" },
                { "af", "44e09a5a7c88dbe67875e4b1e20a7cd6cb60c845efe50ccc293ff53d154d84331141fa3b5e7eeec6759d1c9b11f0d61d67b14098ce318255828158fe0c526ea9" },
                { "an", "ab2a12aa422738a342ecc7e1c5ba4393cd20865cd97cd29b8640754606c1bfae9a30990c23c97939d10d78658899d7c096f9e70ad64ed742cc7facf755e0941e" },
                { "ar", "cea58f11901d012ced6fc14d66d7e591e32f99271f27893a00d767de96eda887459ca017a6393226a3d754470745b37835e8d49ad5a28a4ad595e0b792dcdcef" },
                { "ast", "2ae944730328526e5eb174460699b24c55a4364872bb87077fba982825a87c580273d03241ecda3979a9c9c856cbe070f2aa31f031ef9d1c9bdfa4901ed00a3f" },
                { "az", "461a46357bf07ee2961b9cae5002f36fd1d003ce656c9ba2b851fe3e65040fc0276f5f6c9b7efd5fba7107a6b52ba4a6596401ae8903ca1b4c93244d895880b8" },
                { "be", "024a624e49aadb024be536a4b89717013d967e7f59fa590705cfc2fd1c8671be4f123c0d5fb75fe65de85de551be5af01fda8cc920366aadfca28d15ea784ede" },
                { "bg", "f73965a1c685a7a2d45eeaf95f12ceb2409609718898e239afaa45dea07174bb7312bc617a23a806ec3bd295808b0ec73e4407d3599feaa211479bb9ce3faa6c" },
                { "bn", "dcdc72044ec61eb1f78fc683c478a2246cb7091b4a5c9688474e217e9843e034b48be90f6e0f16f0b8a6f050defa0ecd28ff54efdcb9e95e75673d158eb67f61" },
                { "br", "c0b67a6880d55cb1c489da480862ae4bb61f71995c71d2a6c140b4fca50139350cac8da1a20a321074b9a74218d045d9aba3c91f0e967b7e0db8a341a309fdef" },
                { "bs", "85491e75bb0a118ea42e5a3956b68175dd8fed62e5363f51ba5b1a8056093cd0367e640cdf13cd31079459863a1ac6971dade98bd197f6945b1bfcf8b31a6019" },
                { "ca", "5bbdbac1f2aa779487ec4f719cdea407d1c910e46a275ce95a43e2447eb2352fd518e44c6b165e81f4a8987186dc6115c415d568c7aad6d2b482bd6d4b8fbdff" },
                { "cak", "711a0cceeae699f6880b160c9b749496dfe43e6b621525c9cdaa0d9f4a283ff0c193fec8db310b798f9e8fcdd635cbb795c20671bd86b30c358ad25d83bb454e" },
                { "cs", "57368d35b2ba643b83b482741adee640bc3a8512c722473bbd8eb94d46223e4abaa338fd257549a76fd4927598d0423f1a7ddd1a147d4c2791bd1bea7ce070bc" },
                { "cy", "25f8b3d6b9dd8dac5e7f747823d442a25da76ef859c7f2c86a60065961798247f4a957f92b466cfb9f9c034ccb3f55827767f7d0580209ed338e7db98433b7df" },
                { "da", "7561b2144cea9ab2178b37b0cf9eb93be8c2b371648f2a1008feecfa08485468cb1d4cfc2d959694d474945883c6f76ed8a4f9eca071e691d6e059d1ee4fb387" },
                { "de", "b4908a08aefb72018c10fea2bb9d4a870adbe179f97fd762873c898b9d3c538945b6e6be2214ee04ee30e40219ed0473702eabeeafd0acb1b112565ecc404f5f" },
                { "dsb", "afef79fc87149bb4f815dd084dc9317ac77aae77d3706ede8bd426e2c2832793f55ea95a861f71360f122dfb2c41635d2c20cfe4ffea16cd7260e3fbae6b9b72" },
                { "el", "2b06fe20496829b20daa2174d6207db032b0c2bf8e71ebbd3551020b7fbfd5793352a2885380cb27a84d546f500e8a15343f136c78e4f5dddb40d3efa09fbb3a" },
                { "en-CA", "6ded01a19aeb08576096ce4860ce97940e72e671bfd6d230b6ae58805cfda104b6c5ee05a1d2826ab7d1ef4cb6bbcd049b2389dec54781b348a7f415e6275478" },
                { "en-GB", "8c3fe67a4cdc951c82dcc3c6b2b46db3c97eecc3531ea5b577e882efb4def745e9ecd6544970acfbabe1cc20d14155d25326fbd3485f66a932152856db6fadd9" },
                { "en-US", "fe4396c460b9f7fcd5c53c77cf8f47ef78fa2c3ee4429dded2847b065c1a7a4bed114e7cab2f3d7f6e84e239452b7ee3d4a6f4b3f9a9851139c2b8a84b1a4dd0" },
                { "eo", "c0e20329a5d5274cfef5acc04df78660fc7f59abed5dcc08ece56e301da5b23a9c7073958b4559d1125c4dc2f7b5476d16b8855baa886a0314edbcfaf8ae077b" },
                { "es-AR", "0118a79b40e91a91ffe03c4ff3fdba3a506d9712400fb9c65aac865cef5f5e72ff90277a5b95f5afb11c2440a20368627660219286db0319187d0613f0bb055a" },
                { "es-CL", "d3078aaebe7153bea2f143cc988e5156cc9822e601aba7431a77dbf272709e6dfc96ac2474337f3b4aafd00a763a62fba7d84ea62e95550c2e20cd7d71ba1edc" },
                { "es-ES", "1c9998ccfa9a15b59437d4f85936571c89ff6df7e162d8f146f61a1b863419cd350e0de53b1b885f3dcc5c19285ea07bce043a87c4785e8152f9dcc3407e8902" },
                { "es-MX", "596813536c8a7dc5f4614ef1dfd4822088e968c32bf8efb87185975b90f36c2e40d5e0a98684bf734219ef0bc5570fd7c676d6bb07cdd038cf7cff38ab3b2dc4" },
                { "et", "b73b8a348e366801177890b057d14e325f35fd560279ef1dc262f03e49e0570d5949d1bf1c2341f0e23097288397c77f4f5b8ca5d319bd5ad28e192df45af271" },
                { "eu", "f69a5739f13063c7848d08d1ad57d5c866b94175d5416ab0c0342b28482addfc2b9539870a46483f3cff72fd4269b15ac46d430a2d484e3fad99175eb8442d73" },
                { "fa", "9d0e38489e1b00e698c8cb45662d64d38f5ad2d38b6d126bd240a3eb336b3cea94e1da07806a33dfdbf3a465c096c159c4368da3ffe536ee71a5a29986c1c254" },
                { "ff", "d7b569d58e4e6377ab9dca1fb0caa423a488e140a95e28d9aa3aa21fe1c7209cc43f635b31d3cc4950a1927089a137a2bd275a8138225fb2e7beaec03b267e67" },
                { "fi", "471ffa8f6bcf50278a9c812cfffbc0362495a2d572091a2a366d8c2d5e19e6c6f9ebedf347387d761b2cc8e18b8bef1a07c7ccf35a19d00acb7a39dc6c288e17" },
                { "fr", "24112559e7e84e1565bf9deb779b4c535d6c01b5b667266d2dc1f93c0d62e332d416e3bd08ba2e71b857a19570e2de9014011b55677f4ae349d2f8e8d97ce205" },
                { "fur", "17a5fc6e176aa4b73c603170818dcfa21fdb142511f020f984f8ab5915dab0a652ac9a44f31d064d20a1f44ef41ec77fee3a25a3fb8e8304e025e65138cd0641" },
                { "fy-NL", "036138a2349069349ed8223e4502fd1d60b3bab2a4ddd7bb1864ff868abdfd54ac992b3ff59f9e1a22820245a22a1a097277012beb8680f1dcf46a123ce78557" },
                { "ga-IE", "2844755d98da5c9c21002956643f3225537c2fc5a12560c7ddcfff540c9facd32c5d77324ac5f1501e87c7e375391e8f70d6cbfaf1044d33867ab406ca3a236e" },
                { "gd", "648711f27490b6a109c2823b57ed3a42823d2bf973ccbf27fe966e3acdf1cb3fd7bae96639895c77e142af97c7636807a418412a1b2124a58955f41e14d559cb" },
                { "gl", "8addc0724e95d60412ad632877cc411416f6af9ec8c72b8306474ab8d0b053df5f4d52e77e7288d76750a5f7fb48049845caab68105b3e50fea5a656c50fcdc5" },
                { "gn", "1780b171f80a49d658343df65026c53b3a287a203d85585a011e6d88325ad52665fb7f34319ca51af226498110341614069de0647c1d4ff77d82dee6a17f301f" },
                { "gu-IN", "46253b8dc29814b858f553b7b28c68e1f9d0fb2b92780fa6f9ce3b9dd7b12316d2dc0fbc04ba2b1d521be889d7dd1492f2ac08c49c5bd3619c30763b2a828734" },
                { "he", "6f3c99984d3c3d3f867e78dec72b11e669c3c8bd75e07dff5c034acbcced993c2627df63a24ce0f022638e9ae69e3c9f199784b9c712025d01b0626203212491" },
                { "hi-IN", "5c80a8981c51cb94c04241f986f3cd4216fc91fe3d8b1fbeb6b383a84c2a8fe86375d443b4cb83b79d21a41ace2c601548bc8b6be18c1e1992bf3ef5c4fc1791" },
                { "hr", "d576a9a3f680351e8b3d626579deb2600458488a8c2d35ec2c2eb0cc57572b8a79eaa5af01e133b85650f6e9774e74eef20e7b088f0fc3515d2c77956e8bf4d1" },
                { "hsb", "55e670d670f7b000d9da60c9be86c823b61ede83602fd6d62c82f59e953e7cab2474a23bd697befc7ad3c8e528d7a8461e5790f11c9bfae6a1557bf29174a841" },
                { "hu", "a336e9c3d5149278ac4b209d9df81dbe2123fdfbcaa331eac0002e45b9255b48a843a39a63f21532e6d3b4bcc053f8e6177fd2faf1fde4971e6a99696d3b30d8" },
                { "hy-AM", "850273769422f9f3e3d2d634b17d012dfe79709800325d6ba37a6ade25487159d8ee175f951b279460c027c4fddc9031aeaf91f66e74d5681eaffb6aa402ae77" },
                { "ia", "eb3b2674d534fca0add57f14e5f8dc26c79fb900f7af6a717ff5bb98a914684bd756f71ab74524c6b298a861209b9c4278a63502c9e0cc739e71e4a045c2ff82" },
                { "id", "f1baf72be9a1dc73a79e580b40830b2059eba4c5b6093df08767fc3f78d1e17908f7a01cf4868b64c35b97c51314b500aa35a53527190773cd732dc4828bc7bf" },
                { "is", "c7f4fe4f072007f449eac23e00b668c547a6b62b965889775208db7622644266136b4dc09ac2cb2220efc33137c47ec1e19451827c973aca3384120bcd9a0562" },
                { "it", "cc49e6ae81b0bfe5de83c33c46fc03bdbf84d71f34a90bc5e1a7db5f5739fa965d3705f4bc9fd9298f1089ae7b6915d8f1c6409ce18e8d27ec135768083b3f68" },
                { "ja", "bf93fa943266690f84c1bd04b1747319ef0af68f61492c9cb42b3fe350afc92aa4d55bcad37507494b989cb1aeb4b308968e14e9b94f1e42e8c83a467d121fe0" },
                { "ka", "cd31348aa8f3996853c0ed6911d4cd4e8fe487e1448dc40ea6eaca411367c18a47d0e3f0abc563d2bcd2199387f51f7491a21644c0618fa44b95f41a7693685a" },
                { "kab", "e3b1a3e57664c344dd7be6fa4734e5cc657f68d6fdd73939e33f41b11aabb623050234a2caf64ab41f453af9789c34c7038d5b57bf3313d15a0eaab16435f6b0" },
                { "kk", "f5ad26bf598866d18c59b6ab0a3fe77a02ecfdd8a8e149e36d122333678ea80bb5560652ed813d7c476b27dc236ae6d6b97b5865b035ae1e0fa106fc96d1cba1" },
                { "km", "08e24f017558ee28bed0f5c53e25e75e0957564e9c7e3e25aa5f0333678747eea83b29f9413ea1db640ee49890ee2f7125ac344b1d4e2afe4aacd2127b5a4827" },
                { "kn", "df40190ef5f30aae6a63ea94329c39141f8c558ddc2bcbcce6591af311610869261dcde23bed105219912b20c637a96878724b36a2eaa2cada2c62f3e2b1bb33" },
                { "ko", "cd18569d9392f106de4046e8590600b4effa5dd91aa6a52e5c1c397c4b6966fd2907cf44ffc1c044e56303cbcad2e87ae26b8935aa5ea51cbd2ab9ada72ca0e3" },
                { "lij", "664c54f432b7f7cacccdb3624ede9f35cf1b5698ebf820cfb6bf45e00fc27ba0868b2b16a64f235b73fbb184a2fc7bb2ad01a1d1824e7fa2223e74d6878b9f6a" },
                { "lt", "849d8db04d4d23401ac6338b81e60a8768c73de47b85e49cfa9db56afddd95857c9a84aa9a0e7d41a25b89e8e42777f1aa6e0ce0d00fe8aa70e9a354bbf66a04" },
                { "lv", "30404008c77dc13700fecd95d0ec25944d5a8b0dd371e3d486de3df80a00236457fd8816c2faf529ca711f12f33bbf1f17a55f4bbbf34eedcd1fe19a975542a6" },
                { "mk", "dc2fc3a3e7dd54635a86bc1b3370f486103aa577135e90276e25109e7ed59d560fd259218b269834ea238ba2485cbaa9517aac511270b74710422279585ce5cf" },
                { "mr", "f5f2510267748ab4f1b89246846f07b5c262f2ff9d38df09b1f06c6176b8c9ab88262532c53fe45e528a46b0f0f51d06956b39f705a8b60f8a5500ba2c24e2e3" },
                { "ms", "b4fecb322a6160201ad235dd40cf219ccf28a142ae18ac498da0469dc64b8c351279ffaf48ea417234230e03c01989c9644e057f76085326254ca6f57471889d" },
                { "my", "7f28ba3441e514b41613c170cafbff337481752aaeb9b28ba80f33283ef5cb7ef437b3ba53e4cbdb18c8d7db86aa5ff278ff979ccbc681489c9f68f03255818c" },
                { "nb-NO", "75962469420c0371c2d73847df636373df7911c4ebe91deefd1790a186c1f7d414e78571e87759e7ea0b72d4a38cb22063bbb23262540038e984314be112132f" },
                { "ne-NP", "c7de2c93bc95e856fdc7ff11e7685d036683daf1a6ff0ba8d1a6026b694760ae218244c7b9e0cb799df598e868a2d478eef361fd7aded4887650a4866daa5393" },
                { "nl", "e872f03b9b270ee8cbf86d9269418a7ee1144cd86a2edec55c782e18cd7b5b1ea75bbd4164d848d132b0f9645c469bf019de13758e542a13500e0799cb118b2c" },
                { "nn-NO", "59a59b3f5def6fcd3be43cb9b2107b02a8d8f462a7e4a67e3653644eb17fc3ce578cf944eac69bd440675df100a1b9d7f3ead2de991741885c8e5507d742b6a5" },
                { "oc", "b48f1bab520be231e146796e5bbfb0c6ef5d31bc878425d5e4da846f12fc6af8d75c4eaa2ede68c7ae16d9d3a1fb4d2970197c406ca55bd8d669ed2473d7bad8" },
                { "pa-IN", "b973c04cac3cd55ddcf0cb1a83d47731aed37ee06da84e68731f19961601816f00ae7b58debe5340007e3b01be257e342e65c62471c60633ceb9a0dfd5b16b1b" },
                { "pl", "b15b9d53833eec56070978485b327a9bd3e81d87e03d2c767eb2a4c42ff8905e46b302c9f185641f90ab7fe5c130bbea4ceec583ecf0b2aaae3291f367e41570" },
                { "pt-BR", "ba20177185b42a84aea2235da5ec60e8ec75d4673be6802fcc69d3c53e1c748349993cd7424ad8b7a2627118450bd3a06ca817b346b3a3c4c07b40c7cd2d3445" },
                { "pt-PT", "3ba7268b36010579ac00018a3df4e6f598243e1faf548e6772b2e81a10443ed3590dd2a363d2bdc3f91db6e55b64b2812780641b9626f5f8e5a07a0cb4316c21" },
                { "rm", "5d8fcac1f8cf177595b79be5a2660559aeecca09b4ae1c245e86b60984c74efaef9f02c5feb18ef5b63774d8521321a42075913fff1f54eea46b36af74beb160" },
                { "ro", "321c1711fec9ccdd1b8c599f1eff60afb7b6f7fc40820e670ea61921717df6412b13783a4a67ef4b7c5370efe972f3cfa02546c2bfa6e7dee76c49ddbe54c08c" },
                { "ru", "9e40cabb9a6184fb3212887fda379d0220391de555ac14c5e0d05631c9e96f4c5ffeaba1a82707cfeb3de058ebf0f8b81f5fd83e81d6ef941a6c0272678c84c1" },
                { "sat", "6ae7a453a7e03dd08efd38dc49d9a17b36a42e76c308ce22adf9549b33028a57afef07106b1079ac159565d0e663b23cf39a10ecaa73067845c9edd1566593ed" },
                { "sc", "5c7d5730449750053f2c440e43bf0b28098a5d1a95c207d95c590ef45f9755b2477a4b761079c52966bd603ac42dd1c2c533be29db80c3dc4e12edaad7e3cef2" },
                { "sco", "2e0eee50924f35a97375b2fdf7e0a651314d91122b9b8e3862339ddf71187ba806ebefbcd360218b7689a9aae264c1846e3bd078b492122c0f92457e74ecee33" },
                { "si", "b55e1965551aad06ad7bca97907064feb34e27fd841b64c760f4bf080730ac64a278ef8c57eca99ac1498f38eb04be0cfe7496ba6ddce056a2f33c9134abe739" },
                { "sk", "cbeebcbffc39a3a17cb3a3559c1daacf70b5ccc8881fe2f1540bd189327105c3d30543c1f9dbf423d5aacbe8ae2d6124472bc07fe4a9431275a201ccb8bb666a" },
                { "skr", "414b29c92725d46e884bb77e530e7089d4eec6a2dc9a8e78ca224986572c1d4dd5089a00cc04c9f606273ed4697e6c531833e491268ab290a331269007e779b5" },
                { "sl", "5c156fd34e7917747a7a106210ee8efb8be0bef19aba97ccca1257e3010fbcdf488341352e1010aa201fa5a10b5f26329415b1fcc4beebda17e5713b9e267eca" },
                { "son", "704681edb66e897bd1ec0ed025e9cb7f084377ce6de94a2571853593f0364066f1ee128e1c074d82ea2b5abc88667dfd38018f92adf743c4a1e4cbc2b151f0f8" },
                { "sq", "03cfcdab93da1e2bb3a43c2b96df42e6734ce7abee0447e407d0bc40788994b9cc9bb13e30485bdaabfdefaaab174628fe7b7eedd18e6e72e4a11134d9bb3ab1" },
                { "sr", "cbb01ac18f0a90d98402a1cdb5d9c3f2a7a1c1bab22dddee0ea1782c68701ef14cca65881cfc8b2102cbdc0ecc30b0091eda8095046f9b71597c77964b9f48ec" },
                { "sv-SE", "ff9b7978742c09d57a590272385c96dfb4243fe6784e0e0ba41c176cf5481bfab98b9ac2bb2fac12397ba03638b0b1f39bdf1ec70075775caa2bc27b7ea97a76" },
                { "szl", "df9d67d2f85eefe5a3152986a4ed7ac4dfd11f2e47603b6cf22e53c3c24102a9e45f4929b2cb5a083eb3fc6b2128dcb9819cd92bc9486a00d10d5a88849ee4ec" },
                { "ta", "5cd1fed9dc22775aaab33c50c5a9fcc8b591e90ad3d39fdb8ca79db9c107b5c8ccf40dae496df2091bcb1fa934bcc40127c870c83d04e2eef1cc2454c021e05e" },
                { "te", "eb282c556c6a2c33c6feb9c21053e0eed3d6c2c33ecaa3a20ba35401370e853f6523cebd14d10e1691c0f992793d7774e96b023e1a387de33ca3e535f99b433f" },
                { "tg", "42925dbcc7ff03c8bbc9c94eb708dd9ca063a732b2e7e2a4ad754e7558876b1d5d2be32106e28d8da0ab924f6b2b89c5c1897c9d74d928922c5ae82ef2f375a5" },
                { "th", "209cb9e985324fad49d402bda156820550ae6a4b6fcf968dfd7419b3f7ad0c5ac08ad342678f7237afd22a62fff3f685b205b4e27e410be8c43eeddc638167e2" },
                { "tl", "8c5f0752e6200514fa9855b581e7f59605be01c44bf1552ed2d0a800c78a426721776768f6d8c79cad912cd1314ca20cadc47ca0f08cd587cc03221483d7a657" },
                { "tr", "b8c8cd35a7d6e262847f1cb0020e18c5396d239c3e5a9ae77c896622ce235695fa91d7f4edbfbc3f91a75c34d93e576e76774bd9c13f87645e836369d76f533c" },
                { "trs", "0262a0a59a321226ee26fce11b89ae59a2d7be06d04703dcce0a89edf6a2445eaf6a8a5c8760e1265238f8d57fcf86bb2c0af40cceea2261633a0c31351837b6" },
                { "uk", "bc547abd1ae916505a936abe2acd5b1538e5faf92f660e9c7f125ce8c343009e8cb085f6e6f4754c9dab21c120955a00da066ce302aabd55ca047c79f1e83e44" },
                { "ur", "f533dc2d766206dfaf1978514bead7540433dbe3c6fad820c7cd1224cb440b12c6be79df9ed97054502e0fdcd87470bd01da4b68e009acd66418957d465cedc5" },
                { "uz", "402d2677320daba692148868924c06b7599f6d181b936df3729d907027bbaef8672f32ba113bb923d92a999b9bec4b54eeac791045601c85d3b835a55971d29d" },
                { "vi", "45042852792a62270c5d03f969d3bdfe3c2335c5191f9a480b6f7447d0897cff07e94e4ff367109b88164126cb27c117aa00583360ff5be3a7eae8ee9bd9e05a" },
                { "xh", "9b6d53ba5431bc48a96120bc90c58f974aec238dc3b765bf381aa20a21d932b000c15fde116411531a1788905e9a1ad05d5129be26d2bbba707ee99790a9e57b" },
                { "zh-CN", "5a23969e814d58a0353d991ff8ce6d1e6e84966df52068466a2ec88a811fa70a938c4572d05bd6407e552fa80b888c09a77b4f61d410c3b9bba41cbef47498dd" },
                { "zh-TW", "56fc4cf7e39ab64e5bd2cb23d11b0993272452d00ff1793019aa84406441664b54372c84fee7eaba021e9b2f9c52b21f151668131e21cb4ed34ba3cc07dd5eda" }
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
            const string knownVersion = "144.0.2";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
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
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
            return [];
        }


        /// <summary>
        /// language code for the Firefox ESR version
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
