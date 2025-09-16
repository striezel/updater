﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
using updater.versions;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "140.3.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
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
            // https://ftp.mozilla.org/pub/firefox/releases/140.3.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c890df19ad26bdabc01cadcfa546fb85a46f09859fe267778fcda9105126c51a929cc291558f400fe44c3820e6407094684c5d9daefc4a09088acc62946d764d" },
                { "af", "0d847dd9c5c9763ae02f168385bd1af5da50b0b04221a8c25b76ad0172f41ea00a6435b9d3a9863719037cf9a7482744228c7ee09060887d61032e4913cc150a" },
                { "an", "30634e737111a1fb78c66fc6a53aaa165ae70fb5a432a3499be4ceb2264af890ea6d7ef2114fddd943ed3fbed028e96a87d0d6da0cadfc06035b2b3a58a6e054" },
                { "ar", "c7cb79d3fe096db6673433100eec0257da301c55d7de18b4d5237a648a53821e41a4dfa5c629c3715d30be66fad986e05a82fd48818a4501aef8f22e7602e8de" },
                { "ast", "70381eddf10a2674cf725a9cb6daa083ae6e8c7593b22cecc4cad394e74ba3de7121ec7438db56b2503fd3603842e6ef921b4010184c0e6cec7d8730705a5e39" },
                { "az", "b4ecda35a7b238acdba13ea889532dfefe260e58d266b7d8a4e87281bc3b373faf0a67f14a2e47accd7275d360270b724493a5ce9b55cfac56ff1ad8918a35d7" },
                { "be", "45bcb902ee20dc7db3c619630cc278e169b79cf6aad1a9cf570c7ac670c5ecbab076719bc1f987710b10fe07fc6ee0427055449b80f7722c5a33ec979b55a40b" },
                { "bg", "d6b543b7dd4ac859f8b73575c02459347362c82b318b9b0c422990fc175988de72e9ca1ea82de7a6b7f5088a267378cb5eb3650f1d7fb89cec6641fea06bdf83" },
                { "bn", "88028ba625d3abdc28931e0d27c05308f2e4f1a268f5cd9ceb5c1e77a8b44808c244e12ce1bf41cd75d8fc58b001016f983d116fad932ae620f58faa0ba6b7d3" },
                { "br", "33b463c309adbee2f09fa60b6219ba290f5aea4667cbfec4dac73b86694ae4616aca605dd88a3efaa0780861a8d930622da473e0fe8e1429148efd8a6e3c6685" },
                { "bs", "fa15055ef5bbb666314397eb99fca07be35eca5311c434520b752aa7df63b8d3c707ba60f801648e7f8ccb184eae0ac8b07c856bcdb8bfe1e3880877e2900800" },
                { "ca", "65f7d5a951615e940e674e636cdbeffa6a46b6bcdc23bc86cd034b17a9b42d990898943108ac0ff01b2b62ff4193105a1d5dad71fa360f00f5d3a76dcf26897e" },
                { "cak", "53fa945b10e1791c0e798c4377ce0906c296e42809946bebe449a1db554b955a312b6a0a3486a3b41afa8c6bbc5392f63b663f16ea9c205dd78304d8a967ad64" },
                { "cs", "7ba40f7fea1e8804bca2c14ba394d52ec834f3df184694b52a781cf8e75349e8321e5e779a588ae5ba59d995d98d6907c936badd373e7fc1c7b42995131bce55" },
                { "cy", "976864bf11a712cdad077b437e555723d6f3c023b3c8bb48d75d31fa0b6dc2a4cf621b53f907f5b4ac6f209d9a041389bac9ca487551b5f2b2050b524c4765e8" },
                { "da", "eeb992d3ce1641e0a85987548971247ef93736b75e58951d0c9ddc47f5db6f47c3b1642a109cb651d3fef21f4855357f1d6cd55943404cf64839c24498ed4e2b" },
                { "de", "4f8b8201da894dc23af2accd82b7a670eee9ef0d18cb211b35afd91de309fa8d87fb22f1a32973a6dcca3a1d459da60fe148d446f4a26d2199393dd79552ad20" },
                { "dsb", "6fd38864751e789ca1060f5311cdb4abe23a280f39f8425f1b43aed1eeed9ab62bc447d07822eee5daae1d4eafc52aa0187b334edf00fdac3f288d186c02cac1" },
                { "el", "73dfe902fbb3e08c0d03cdfe3dc38772d5d72592a0e0695aeab5e208950d25d76355fee52401d927d2a573e6b2b81c81f9e871ba309d58a466bb3816af08e263" },
                { "en-CA", "6f8eab54e178e004ab14bf42489015984ae2bdc353849668a799603db7620b2ae891b93c4245788d32142297465b772d0f68ef6a823c94823eb84582ef27aca8" },
                { "en-GB", "5edf065de6d371f15c05b9604700cd1c54ae1a726eaa3e461823550062272fe656383f128407a0fe74834a88cfda9d4ec510ee74ef6f339b27995783362a5c97" },
                { "en-US", "9cc894d6a8b3cee5198e9e17bc9daf5d699758a785b481cc74470e24735a7870151f60b30eedb88bb3699e23caf8afad9a6a0727390f286f6d1501c1b1060825" },
                { "eo", "951c1ee01b7f47bdf86f7ec88a5a4c5d375e5824b14e878ae1b7449bafba0ff45be1b582bc94c43ee15b459c2f1855c48c23cf0bd9884ae84423a130e4086057" },
                { "es-AR", "c0c1732b9a77c3cd963d8e1a220e1342c303fbf48de0fd607e0d998fccf407d5b28475a7c33bef2b47df3fa98d2e1224dd5c1d061d090e110da4dbde30cfc405" },
                { "es-CL", "f576a064088d5b6d9b72fea978f9b0758436ad2c1317c859c30a41ba35b1c9d38f1593b5c8d6d89b439d8c210de9be33df0dd7f4e28823ae3818d947981bb5f5" },
                { "es-ES", "aac9b9197f8891e2652c6472f8d563fff3815b3e5f8272e2bb57f31c75dc822ded25fe5b84d26e9a3b31e52b33cd5d10ce9ee1b2d2e3dbd70e2d01d88e32583c" },
                { "es-MX", "885e6cd27c28ba529b4e6d7121c1a1913d422d7edd8103d68e7e8d0d46e20f25e73524722b1be5bd447ed2e42588d83414416974bdcf295a517cd6c55d451b83" },
                { "et", "12d4eccb30fddd72643dd4a90ad6d68e56387f4d2b7b03111e4a84717bfe03ca3f161cd4e570ac5ae0ea542e8c5ac1d23ed298e01d5c100f045b24bb83ebf1b7" },
                { "eu", "5acaa468c71a4e5ac77934b4ac8f7ca56e1442d85b5fede4db14a992405dc004baa8f2752f9ede1fdbe2657229b7711aab42ccb134fad48a2294aec563eef11d" },
                { "fa", "4e66cce4ddc88f93cb2f2f1270edf2ad538d0321e4c4c2a8cce8a6108d91c77ea9081850f7144c7e6cb69ce4989ed26cc3fddec9b1fe6558697e449ee6fe288d" },
                { "ff", "3c5a5d79f01309ce2c0fc24106f7666abacb4cefbff2cc374ddbfa5ca86809191e1815c9bc4d7f4c5467203c460293216a189fddb008c19b8ccf9a4ff69832e1" },
                { "fi", "9babe85eaa3837b09c40f90491808b53c24996f817eecab5339b240636cedbc3916aa117f1988c0a291800558c24007a7bfc649ea0a4493dcbcaea1afeb548e8" },
                { "fr", "87bf87e88dc7b2b8c14d21b7ea1f9f8225d5df6aef859c05093ef7b326f1b04511cee5630fb7ec393ed2daec3a6a052da48d6b214a8233c37d852fbb37ec1160" },
                { "fur", "738f20b7d08401848c3366618af713c644af8124925bbc1a5d07167fad53bd32dfda0aeab77ef3a1345dbecfd0e2a2aa3ad9b40d1f4e169c6b196e5e4b7419e2" },
                { "fy-NL", "4c67f96a3893a51696b35186363f94c7c52d49aa594d3b6892f9eea380320d5a4921c6810108b2881d967bd8afc5f7245dd1f6380111c89b571e04186eba7caf" },
                { "ga-IE", "a7eea37e55f34c3811d90619c47bf0b98364bcbc68cab176cb8bd7b0a3e559275dbd4a0421041c0b6157616e32308485c3f3e09f4d7c21af4f5d329779c0c985" },
                { "gd", "1eea5a20decc46439939df445ced872fe2fef302a6aea0443641e40cebfbd981ab1ce4e3faf1fc9d8177bb871658ab0282c1700450f6c236f139de6360a6451b" },
                { "gl", "7bfe6a93d0588c28f4d440f00f21b29afe842c5228361b45a673d797dacec45d7a7f88be92b7a4feab65548e42b4001ab03d92fd64c830b417e497e9c62e29ad" },
                { "gn", "4a07e756f9eedbd82090cb10c997830745531d8a14652ea42f55896ec9c16f5df54c41059626c88faf6cd9680de1f47a81cb78dad829b4f8a648958eed94308d" },
                { "gu-IN", "bf90ad0b6c0fd761489bf3428f3c0a58fa5312da5d1f9d80c0046acdf36f6f4a00fafaa084ba3aeb02d29d1a45b05751ca5eaa8183e8880a626f79ab4fc5321b" },
                { "he", "7b016535997825c198b59949e68c8eee262b54f3a56a1ed5d0e601f664382c53e1fbc6efcf703df8e0f3d299b982bd2150837e7da8b3c57f46f8e6ea5d7de258" },
                { "hi-IN", "f3dc797f3fac8634c06aa60b2c6cd2cca4ae17347659ab3711eb28553f385b5c7d975fd2717c99933e01c8ffc76a5b83c451adcf45222b704928f26040e38e13" },
                { "hr", "d46961da8df7a18c43650b3004692875ce1a8fbbd28fd1c7c2111e14e29e9f74149d02e512e5245db6f1742215627395697866d03edcd87a7a93c4fecaf46551" },
                { "hsb", "2c347515e4c6155a9b5f2bb08da4c538780a095fdd2b07c72ba32afe8a2139e761a161e136dd10f1a093e6dbc4e8c5d38034ed7fa3c42f63bbbcc03dc8a67792" },
                { "hu", "ba35a89b1b7c910c832b8a65ee19af4e4e1cfb8275f29b3c6e24ead4d93a889183771edac0493f79ebd75306f62b3ffd9fb1a3294df49fbf5951bff53c789d5e" },
                { "hy-AM", "f370a6b460b87729e68949d56c2a51a0b4cfd764198769327ac0a9ee152e5423e13b62624b301dbcd56d56808016ebb9617450e4cbcc8892fcf65a1c7e2bc327" },
                { "ia", "ecaa1becb4eed95a620b2aa28d94e434e9a2fbbc4d2517d145be7feb527bbf3c8acc5f98da9eead96585b0a2aa2bdf3935950c8273044634ceb8f15382602307" },
                { "id", "d800d5e8a3bd03656ff7fa18770d49e80a605eae03161a7baa636477a263477c1e3f9cfde967ac49cf95ce686ac20b491ad7d00f6c5f674684c65c2ea0d8d4d2" },
                { "is", "e954f62ab74710f81da1d0728272e7149044381cfbabdc51fa7bee8180d18388616fd54cf4edb40fcfa306a2af9cd7439271080b6414b6c5042e87f9cbefbf83" },
                { "it", "a763a492062963e3f295c18809bbcabf4ad33b633863dc1c18ccfe7b042e92f3def7548afaa8eb65d879a6ccaccd73bc8a2c12bb959d2be51edf2ea5279cfb6f" },
                { "ja", "70dbe1918d6792b4773636758be6bcf05b0e086de5eeff08eba0fb40ef8fd368c3cba6794c5de74ebebe964867cb6f372f5ec1ab034f77fb549141d42e75b0d4" },
                { "ka", "98e8bca24568c083498dd6792c92696ed1976e8d3f2add5c4246837de51485effbebc6bd691101a14417c975e9e52c61d13c529495798d8efed3be68dc8bcfd0" },
                { "kab", "dd4e61cf6ebfd27c04d1dfa2f4614497a679613d2aae737dd6938116404c57162eec017fcbe010cd6d0d3ffb9c84bf41891fd4818ee83213324a8444c3417507" },
                { "kk", "876f61cc88e50e12100f3328575930fb5121784a8d7441dffc098fe3197c8ffd6facaa50465ab4da2ad1a6bea9e18b3125323954c4cea3d7500da9f84d84ed45" },
                { "km", "a5ff548d5ff86394b1f5722647d092fd23391336b926e0e64be24814170180251fec16273681068294e743a6481d76e4f6ff1bacac77ba0cf26604ce60452442" },
                { "kn", "c0a3c8c086351dcf131752f841317a9012cec0f9afa2e9f035b8f73dcc66bb250bab1c25a81f4730b0eee98571e2dc49d0cf80b0c4722978d5d66aafec95adc0" },
                { "ko", "6a367685cbf7a9d2e64a5fd6333d1216140d7b3d937b136d5a0a94aad809cca75e51a3d371bac7a65d6b9a479d9c804e526c79658113a5095016649a7cdc6654" },
                { "lij", "e147e98a5e7fe6c673c3527a2f2893b4bd04d26a79bb0a27471eece5ff83b10ff5e0cd36202af3965489822bee6cae36ed3502c61f564a16efac5ce82c41628b" },
                { "lt", "e0b7920d7b0392c3af5e415fd79df6506b31352b0dfbbdfdd0be85e6d9dc7d2f7596129f1d7cbf75874a2bd7af9a284d5f2ec6f713504ae178acdbd8ca177440" },
                { "lv", "5b6f47bd3f9afcd83954e12843d73452f3c7c4057147bb53c42bf675189fe5323386065e09f047ae8cd010747459159a5d82807617bc2068613c5f5fd8a30b64" },
                { "mk", "fcce6ca3feff7c943afd217ee760172d90a207b70b0793bf7a9e2c566f3d687597ab292ccc360e6ae6f78c720ccaa72f7eb50aa21a59c9a578e94b3ae2f074a7" },
                { "mr", "37e7688478aaecc6d52554cd86f23f09f97bac48424692614087ea9410a2ad3c21a7263ae041e7c06c77b6a4f8e39a6072dfb07f247b57385a30767982085dd6" },
                { "ms", "db140dfca50b63ba9f6a834246ffa4b8d03b1b0baafd4394d48c329c89f15cddc43b9d6eb23becadff1b6080575cad1313f0af4074219c923a19665a392ad388" },
                { "my", "9e9b6713defd0e75cd800ea7e37a790ad363dce0bc253ced06bb0a37c0033838573f11d77c8731ade61c0e58a04cac450a1ef4b4d278374e6f2fa87a2e243623" },
                { "nb-NO", "ff51b2bcb509df50f19b244ee793c07a21286b065a6ab1907b34919d2717f1ee16c92252a28572b2eda9369e69470c6a03882daa606077db620e27ad6a5a4da3" },
                { "ne-NP", "af990d511ae044ad4ee0b633ee7b83cc6c434bd53714f789903b87a17bbd25c0c8a7452b5d641b329a185eacd1a752bff2997fca1b895e25053ec863713e80b6" },
                { "nl", "156bd1b5b2db60e602bfac8989b854bca25fa6cc7c2f94150ff01c97379e9ad88d0bc21dc6e2177281fe711d18694fbc09e9a73f3d5b58fac4b4001fc36b4790" },
                { "nn-NO", "cb4c315074f09444acd1de9459993fff0ca8b963d16bcd3cf74b2f9e2e723b5438463f20b83e4b7f30483f1d6882a8ce81d4f7fc75ad524456dd68d9bdca42b7" },
                { "oc", "d7600dcdd35b848c4b57b728ca07a51e734e63474909934691347053daef6bf6a3cd24d3cc8634d54e26ee00700f50867d829401d20d9d7e239ed944a73e9149" },
                { "pa-IN", "d9c49474823f0b055da7b1abc2faa3e17a7e093cc64a397c9eaf4b4f7925cf82b5d3ef6bedaead3bad187da191db3dcf88afe5ddce32a79a978498f46041b3b8" },
                { "pl", "af25900d8c8416397a14f15b75fcb7bc80fd927690b1b67afd7538702f35fa4bff160096902eb2a48fd73b4cf129aa9dd0bb07c1bebbc7ed1facd9418c96ebdf" },
                { "pt-BR", "8102e751fcc0f5097bf5c7077f6a3522d70e4a988b548f2ca93695040de7e6509374fcbc235c26e50749e9283b4acfc1e90d1841d77656e1d32b76752bfe1d23" },
                { "pt-PT", "18764085233ad7e2f1fa8d36195e8073f318bda8267432092c81452607616ed78d52d0d4874ecb9f05a0852363ca796748f2a99f808d92e6c0f5138928168dbb" },
                { "rm", "126b0d0a6da59f40f9cfb37b59031965596debe97f95cd3ac310dbf8e2abdb8126e68d4e9e83267e8a1e18e93dc627f100179480f84d2d924c54df1d88ad488a" },
                { "ro", "e93be666525338fa5e92a9dc94644043ff95bfbfd48c70aa6a37a7dbd3630649b0a4f570e2c86ad8a2246af64283ceff5444e7c6c9f6482d4b50c3bbf896a210" },
                { "ru", "da7e0eb8b1cec91a168cf304b0a7ae84f78036cced6be49e83c31fc734ed75f52a66e4b7e4f2f79ee387d3a1c8eec860c5fb138bdecc242b5465c4e9ca461f9b" },
                { "sat", "aa96a5ff3a250334c79ad44578547a11f8de1f8814f04450047e4882b0a31b8172ed1b502626fa4bb3b97a4947d065881f70dd1fb8dcd9977f3e19a225bb0405" },
                { "sc", "8a1de00a56de23e1b17733813fe75ea029d93063443eea20955cf58c81115e73890dfe653fa3587c825550a98da0d72e0c3788bf33a6d8bb2441194e7f417e72" },
                { "sco", "7135dfbdb955651a596abb2ee87b9140e23efe9c31dd79d76f37070ad196b3af37aa339f45e5b85f731e83fd2dc1674adc923701f6b2c2fcb507ff490b62957a" },
                { "si", "d6485f0ceaa4c5cb5dcad89bc2992d1530655d3c06e67ac061e18415e2bf7f9c47a159d6449ce4570883160b565782da6a972d42dd492be54c868ff27acee058" },
                { "sk", "49dd75e99f9bc5466028db046d1de0a10d83f9270fc359426ac05374523b820b67107eabb4dc9287bbf8369c34218b571a87d274f2165f416385b8a8c034998b" },
                { "skr", "fa7e224da750733980d1ccf06d0b95f2cc38f6110e54e5f42c8a7f03986daa2223bc29fa3f91935f6dd26092fccaf424b4d8d3d42460118970a24912af8472cc" },
                { "sl", "011f67c521aedcc7cf63d31ebfc8d2a4504539fa823c3e3dd8822f7b3fa895bafde09762267fcdcffa9a1f5d5d4396909cc1b01c99b1c20ad22cc532342be784" },
                { "son", "708be18f41474079b527d4a926031dffe0a079c689c808e6f39f7be3a0580c6bd7cbbefbf975ed0d3d78c1a1642a78e6c84b6fcec5391a63fda570286275a081" },
                { "sq", "b8c7704f668b42a5df26ea1f77a54228bc1092d09596a207d54386c170f491d14418683bf2c99fcb926e5283df68a664cdae8abaa80ba74a00c48da5c9b569cc" },
                { "sr", "a21f894d903c691bff21186e5511e3270e5814dba8d3f51ff4eaa7b7879cbc8a841c1ab099c04aebbb137d5ce776f0518f0235796a3c966a93c6174605e25d2a" },
                { "sv-SE", "35cc525498874e4e33e26a058913a8a9d651d96b0debfc306968729daab53367bb5d3e14fecad4e96ef38cada491c5da7028a6087039ba45823bdce489b6edd7" },
                { "szl", "e871b5616579af3f033c6a5488561820ab55688938666f2029e8f87e602a6490bc757121bc9d901a569ea1460e7cff84bddae268731109619158a2fceb1e19de" },
                { "ta", "62b5989b559b2fc4560b9103078138036f7f80a036f176b04cda865ad65f84bf3c2a4c6462689012f23d30777cf87300499c5be18ec3925ee518824d07593eed" },
                { "te", "fe2782092fb8020cefee813ae925d2f80240884043e4fe5557db4c71753bee919d14b8d32b1a2e17b4085fc47c98b2c952ef60e0a8fa6a110dd8a89467880794" },
                { "tg", "09cd2f36476c2040e5e62a770c0e48aafcbaefa3eb8f0f155484392bfcd5b243c20eaf57ff60935c0721edfab107e2868a9fbcb421c1cb3c19b4fcc2039bcb94" },
                { "th", "0145e56864ada50468dfca955a208c96c1e2cad1f228661f5a459ae610d4cb96f476db7f0d1b25d33ef1088e966878e48a7604be01a7e546a5edd49123a469a9" },
                { "tl", "866ae6ce51fcc9221982b29d7adeed2cd048a5037e6b6cd1afb8a1183cb9597492cfd33056a54eef13c8cd253d224a9bd0a56db56608aa7458ae20b5cafa769d" },
                { "tr", "c683afff291f924448d4533052cb5147a20b4c3159ac2376479b3cf2258eba0a9dae92f1be20df5bfe2becaee38309455ccefea9643779069363946a8c732274" },
                { "trs", "d86b0b68dc2ac4db4df48df5518a1084c0685d66204b61f867bf779e86891fd9eb007e779c29ea193f2215ef9228c93728e07369537e2d7bb7dd8510017bca3f" },
                { "uk", "688297aea9392a5eb8370a1cec27667952aa6b4900da069a65100f582ed1a7797fb9293ea2686a359b925eb293be8a122f33dc292ae868539a651a7bc8f11033" },
                { "ur", "2e4bb39944622433c27dc34b66c98701cffb0dbf1e2483ad5affe9423ebb3e60419042b1920c3057f6bec238fe4111019de207b5bf51b5bddaf066c55395545a" },
                { "uz", "191551ee9390ae190e7a9aae409fe35166d01ec8d4b6a165d55c5554ea33cb053afef7ba6e4d9002bf5b9af7a93556b8f7cfb701cf93e23828b8812d0cea0337" },
                { "vi", "21f0964be011e9ce1fd6e9348da9704cd82018a91a1192f46c5b18159264a6d1019f43c5081a5b0ff116a487911a5d76257553450f450af5d733f449649f48cf" },
                { "xh", "dd6b3892c3f2fb7ca978b3784137bb1875171795cfdb1f000f37e07eadb40d8e9de5625f6d98f80a58ddf6a960ca1d9d429b09676a73c6482927454ed18c009c" },
                { "zh-CN", "5485655c7bdb014837b4b702b50ed14ec47539f82f95205a349abd2bbee3ac653efaccac3fb515126cb6af403ab43b0c390024f3f4bccc34e0631b83c7da8adc" },
                { "zh-TW", "95aa765ac21d406a45b8b4a87d31a5146a73ab2011afbafa084cfadc9a6e164b88a05e9ee744dc3fb7e85fd3bf2113db9f5141d384365145ad672b33d6748701" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.3.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ef7a33e3fa84066c0b4aee4a424077979aacf7120a9cead679666eea8a91f48162368d31baf826bf8166afd9ce3b663beb17875deac8df3a0266d44e41202cf9" },
                { "af", "c998fb05e1eb22e68315684255d7403e0ec0b6d6d3e593386e5456bbec831edaf5ce2602e31f93c1757688f1a293d9497f786752050516978a88f50bad981bcd" },
                { "an", "87b0ac65ce25e9daa15b9cbad27ebac0e59dc29fe9132c293423853ed4e1cea817ba6eb79464e16271a3f37eecac7c52767672868a5afa43c9cfef78b7e77e25" },
                { "ar", "be703bcc7dc8c4aae16d65d86311a857b19c6de8bbaf1842ec3c15326646eba6fda0cbc7e19336d5737e99a5bc24879e915916c383bc23df6afe8a1fa3ab356a" },
                { "ast", "c2dc0fa995f647b3e9e801a87f27606e20506b2ade3859d13997a8016e912a3bf7661dd34209e9faeba8e260fae6390a22870d63e42a99d989bcdb8d26e73593" },
                { "az", "18e2267a955b440c5c6e34209dfca4a788e329220e0d93a100ddcba25e0358e4928a0b0a3524fef61bd2667b023eef8febe18c0f8ea6d1b84e88385e86c9ef0e" },
                { "be", "cbbebabd7e0d9dca0a14bca4858a0c65332990c59592241266ed9c8c021cbae7b00b8e65d39c250b49730d08ef63e0fe3c00efd3700871c4507f50ecb0cec86a" },
                { "bg", "e785a977f908f65c28415c60d90eb452f3de8db243b7896152397d3616c9a4b15fe2700572eb5bc595fdf591210f72d36ff54519c0ebaaf8a4ff28c522360796" },
                { "bn", "eaefc404ff4d2eb4432616a3055762414c514f64c1a55b1ca60070ec937944515e882fff63848b8379cc2cfbb041ab2364a2022c49ed006c935d179880ae45c6" },
                { "br", "ea72591ff6653eafdb1da0e3a2691f663c9f0f1315d859f267fefd5a27f262afe497ed1f0406cf6c66a8efcbc1954be30c50fb96c35baeb785a05e98a95d0ede" },
                { "bs", "6709c866a10b5bac646ffde4bc2d1bb313aa2b472f55160bd3c4d5c247143cdea5cd8b8b9915c987c9427e2168565411f423b3387f902c5d5bf4ceb38ecb3ea5" },
                { "ca", "78cf086c7e4eb1b0694eca9af0176908434ce9c04cd1c8fbc6fbf6ebf031f0c2708b673c242ea786b8dbd07ca0e00e7c8408bedfb52cac7a63f9bd18c1dded59" },
                { "cak", "aa68c11d5f4a2060b5665e7bb7ff1fe319fb1f8a8825ab15229be2a2b52fd4adfd9009a1036e1e08d61f41eb1c0c63bfc42843cba94c41890fbcb2c068b42dd6" },
                { "cs", "d777939993d629d59fc18145b2397fbd1922d95f03e1200ff6a6740efae5284dea39368ff05beae377424071f1030f2277e325a0e55aad03614094d780606266" },
                { "cy", "0635544c8d6d7323d52c90625361f865c6759840ad789cdb0403d339659d1de0d4e0fd262a4963d1669c3e2d17ff7cba8667346d22baf2e7220f25cb05146a10" },
                { "da", "aef7be10830ab9d0bf14a853bf4e0eebd2f329c37f3af2e61f8e61bb6bd0326e4a3c65a2c4c7169d0cc175f3fec332682f0eff57da20bce6459bd25cdd74f5ff" },
                { "de", "4da082cc08695b236b5472025fc88c690b7df46fc80d623c59afeea999ee74878660d9b1677efcd055aedef425d891f63a8032a0818a76cf9b00be9d6af4c0aa" },
                { "dsb", "fb5f2f00fc63d9cbab96693cb881a42608b6cfda42f968370a4593a93bc7065cb13f67290c842e6ab466acd7a4549215d2e009a2664a5a4023a1989b003ec90e" },
                { "el", "54b6b894f8d129152a8f6a9876a43994846c6776dd280def5af070458bc5ced009c7cbf44062c3756fd76b6933425b9b9c937a964dfe760713371fdd641d4df2" },
                { "en-CA", "8189fb30589c5c0e1e539d49fd03544a2bbfd427cfc78f85bb9f8ba1ac7086baca15b5423770986fca522f8998b0944fdc7fc8fc83dcce28c4442b7c03e426a5" },
                { "en-GB", "0ab2b09380db5331e2c0848b1dbf18b3381c5df46ea2e42a882615cefbdef9aacd0f819057538f8b3ccb0839137f18c77fefc3a6d42c68239a532b8149538497" },
                { "en-US", "13375b3ed65bc885d396f119dc67c32b0788462d65f27501314fb6cb2cb959b3fd79893b1a663b130314a14e183f83b993597a09747bc02c2c8742fb6b6fdb09" },
                { "eo", "a46e35beec546c5954e18b77834f02f825c039054fdd03261e2092e799a367fc2536851deacef2a22c715874f868b35f1f79def54aded6d6cbc751fc36da18bf" },
                { "es-AR", "4cdb476c86ae444f6b4fa50ca63864895e87dd5ae2ce6713aa93b240f3653185344cd60ea3a2ff59444647549fbd91c5cae30f5fb7af142163341cbfe48b0b13" },
                { "es-CL", "5d4f4fefb3587d76e8cf3c9375f3d40401fb6636dc500c3f34122f40a54608675fd95eaa8dc7a28a58d47e52d63274ed81123ca928179c2df90e40df4ee8cc8a" },
                { "es-ES", "3d17f2b358899f743aacb459bb78b58b1ffbe3d6508519e1442829b5ff38bbc0d47a0ba6f276a6d3a8864649b2414cd83d8e2e3841921716bbef486b40561c38" },
                { "es-MX", "2d71ebecd87984a56ac4de9a5f9fcb0d59898f4cd28664e9cb4635260615ba134ae9cb7cb6d4ed5437a94fcf108b77545b432d6d4793a22a5408493de6094d77" },
                { "et", "790edb14791516a763f6d79a6f5dcd8e090e3a90dc49f1e3b0f819d0bee783323f64d349f7d981dd08733495f2f10a15958624c345606394a9ba301dcca32049" },
                { "eu", "1d354aef6e3ab9c0b4e4cc23eb9394beeccf9baba4e0528b7f4ffb10d59f5091988ba1106b7b0c951d271fb2273d75c7440814db97aa0d3ac9abec6e64284d2f" },
                { "fa", "447909cb22eb65e4dfabec69e28d9a90d45913f3187c1ba85e53987906673ef45ba5295fe1a17bde586b2d1805e254e16e2fa684bec7d21cd880047deb100a90" },
                { "ff", "e3ba9667e2295b551038da3f1fa9f63685b2ee6227aee1ffd4470d2d1dfb24a0d3d3ae390e2db0fe6129ac8164184a294fbc7ea7c446b1dab2b641b48ee83cc6" },
                { "fi", "dac33745a15c7ea536c67c98ce890e95daac1b55f7c343d395fd51180d287c2fd358e5b7b9128f286c177b1b31986d7c42999c53bac9d59fa4050c8a6e524037" },
                { "fr", "03b078e659d53bcac4127bc2a33bb29bbd0b56ff5c2fba89c90e8af397c1cbcec772e9331c083bfb123e97c3e314fea9ce28ff0d5ff383017d81ce7ef341e032" },
                { "fur", "b218585910b228054652529c8f915351bfe6f70c958a93b9cc27d9202f7f510e2a0baece4087e8326db90956a6c6d9d1aad83b927e643475cd8b80fec40a1715" },
                { "fy-NL", "431a04098e32aa047ec5c5a7e24b8a550d5cd086fb957ba99128119199760ee7c338b034382f6cb3ec6b650728b89471b58bea84cf2aa5fcd457d3f92a38457c" },
                { "ga-IE", "f0e3f02b59da16897a256049936941765e7638bdc5361d3273c42c2e5b8ede96f37246b55a22e9d62375812f51f9c4793aefe6431da1594b6884b8264ee51617" },
                { "gd", "3491814f263213af7f2da1e7abb70c25bc5b0182d3a551ac55a3bd94a90f548cb25cfb53518e5367d0996af86c91bd637bc777c22cad2541ba4175916b30f7ca" },
                { "gl", "73f9255e3c63412a1b61dbcba91e99572e5f295be1cbaf1142f87d818fda7cc747bd90d2e634af49b141c1951f524ab2a0fceaa951f87637bc75dad7e7e6e096" },
                { "gn", "6d30a856d1a09a55bc5f1849b627d3bf298be8345926525975139ce81bc8f35d26756237b383dcd94cbdf5fe46e9e0d70fa682f17298f1a6c645307de75b98f9" },
                { "gu-IN", "c6ecf71eff1eeab9e46f0fb08221f35ccb2990671bb0a22fe336e2a871f4b6d450eba3680a0fad7f9e6c83f4e49df72c89d1d785dfd03a1aaf53ca14e036cb49" },
                { "he", "a1eb92afedc39658d2c5d0d58ff4cc20e07e6fb241b16e1878029fd1e886182e3602e9c7c011904a4343d3ce2687e4f69280e2cd81a1ccc3295723e14545c67b" },
                { "hi-IN", "c095dfac47f125ca8dbab75672f0eb626967d4cfb6ff3d59844b65828763bf9b89dae1285d182ea71b3a1d86c19ba3d8c09b1d457164b929f807015f1280ea55" },
                { "hr", "5e7abacdeb0da88de0d480ff8690655157a95d4bbfa8fd95ecc2ac7fa3f4d3097cac9b7413891253770c7e5729f785b217f6ff68cb618409c1e5fe214c9d1596" },
                { "hsb", "59d00eafb8408996a107094ca99b2ced5a5e410e3e6c25801a630db653530b120ef248ad655dedcce9293728092ef891b78c2cf080693e6b5a8bccbc1abfd414" },
                { "hu", "be887ea8251c833f6ffb90c5530995a6500d11a5d63f542b823d9b94e0a4a55fb478599611c10209bf0c9a67a2699c078536fb5e358483cb900703efe478fcdb" },
                { "hy-AM", "fca2cc7c16f08e3de0d92524c9f1d53bda1343be1044fa80c7c6c4f33988d1ec5fc2bf5dc196a68036f951a66065a94f44983665777caa620ae53771ec37a438" },
                { "ia", "6f64f6d7463d15623fcd66f68e6806e02295d40a9d95cb5c6b66ac44561177aea0f03e0b1b675248b0334306d26901738985e459afaffb34d005a6cc6adcaa67" },
                { "id", "fb857f66eeec7966a4a8aa2a7c7c7061996f35b4e89a6dfa3f25234d901b732fa7026318fea8eabb0a51f237988c99c41f55310d7e25781b3b5156812a799afa" },
                { "is", "f92a65a8e83c3c52d10f65199d7f871223560a40fb0f71a3cc8fdc4003a34aabc8eb466221ac2e85ffd4a89fa0108dcd84db1fead17478ad60bc9390265ff95d" },
                { "it", "36d8e7b88430b5b0959d48aa4b8ef34487e3d2c66e60e21ce3f2cb731c5814380851621ebd0988a0adf5c05269c801e73deddc530642ebf8efca5877a200c382" },
                { "ja", "af93c6ad99366a72990d902f76535f9318a2a6143371584c23201a389bfe3716a4773cd245958c8b4ff5acbffd9f52103c22b628d661006cde4bf5614b50eead" },
                { "ka", "60e6214014e8964a1cd4dfbf60c11eac4377624b856045fabde8fa60679fa78388e4d556ebeaf88fa550e87a468dd8255f500d570e015214eff9440a19963c0e" },
                { "kab", "73453a0718c9adc382971ee4ee7ca32f3d4d009bd565300278669fce33c1d1f3aff1c5cce2833e6c3831700c6bbc0b37507bff201ece458c75d456d41606cd40" },
                { "kk", "2234c22c07fcc524e2adbcc92c7f5932c7d959c6dc437cb283b8e8351e51dacf3bef0d7ecf06ebe6cc57da1f18f8fa960455c918fc6df402d2fa688ba161a989" },
                { "km", "34beadfb97e31ab0004751a60871c75760149056f26c4ebd4f80c4eee613080f06e154d498c8b2924d69e0a0aea24366a0cf6043b782e7d598ae31d7a9b81a4f" },
                { "kn", "5b2ee1a86f61ebe2988682a0cbdcf440c6cd7e437f501427946125ee9dd355943d4e2d6767605833df0de84bdfc85b32efb5fd2d11f47602c0233fcdeccc5ebb" },
                { "ko", "d0bae670c0df5caa9b02f8476d90822c4c71b368fb1e7c1bfb73323f6c6ac0d516df3b9ddb3add42be939fdbf43af67f17b82460f357e030bb0fca9b1a956161" },
                { "lij", "172e6486c959219e4cbcc9fec93d8fd000881944bea7d63f88e3a3d1a03b4d4e0cfef45432ae1512a4989685bc0c2f12de01f165204688e10d82929b4023d948" },
                { "lt", "fd6b8a903ae80ac54216cf6eb3dba8e0e396c9bddba685819d34dcd4bda7487ab8fbb14fab8151c73921456174c6521546c451f292b8f62aefc567698b01bbfe" },
                { "lv", "373b42d29624477c0d155579adc8e2b3396b4ae7937a5cbc9cf2131e7dfd0b4fdfc7672b0d8c0bdf4f2e197681342275babb4ff1bb17f6120511f8178d4aa5e9" },
                { "mk", "096f68a02cfaee0466e16c0493051fc78591bc71e7e636c6268256fb34563f86776b3a4ad4c0efb33d5326f324eb7539423c34de0c532ec3d191622f03b476b5" },
                { "mr", "acb4585074579bb06f89dbceeaf9989157761daaf5a23b6f8a8820d909b67e8b94a41ee1d9eebc630eadca2c0027b04732372365a9059f84511f601c8d8ee5c4" },
                { "ms", "6febe6c33c71753861a38b74083c37e4c49799a680c0a513328a6a353f4d48ddd33660e83376763b062a3812ef171a7dfc716a850c1fe3df73ba2dc491a3cfe2" },
                { "my", "30362a7f0c8d99e88ad223fd9444288b89b9652f078a1f79b7f7898cfa28dd93a6dc62fd7a58ce9ec1c24151c1df4d0d09d9e9c8b2da174146aa5b72cb90855d" },
                { "nb-NO", "5731337efd545256f2ecbaafe590e98f596de981a7a5d626655ae2bfd09b782f4f887da84858addf490e0cbafb046bcb8b9e5af6b00c6283d991f6f93eb562b1" },
                { "ne-NP", "e5f561d60f950e986cef7989586d8ebcb8e3ef755f85f5c78ae972bd62eb8b11ba5964ebdd23f837f6d657334cd547b4ed31045390f50370afcfd21b2a012b3b" },
                { "nl", "411fdfb43541d26e72fa9a9cf4ac72d0f17aae352535fd131c815ad4d5778ef1a5050b797ba6949f3638124b46e9cd43eaabf60bae68a0b5c2844530d3119921" },
                { "nn-NO", "f69f72e191b2c275811a290ed8e178a2af2a6a865c06a63fd8f41fd23e077b86790182429701065897ab20d994746ba71cd190d4bb065473a4227ec7c5327fd5" },
                { "oc", "f8df7e0ad70f2a6ebd72b5b8ce4059dd6232ce0d99eb751189f425e4cdc7128ce827df8ef050a1e778fdefa5cbaf5ee6c2db2cb83c0d148abf7bc5010a3c7c58" },
                { "pa-IN", "797e8534220076194582db32a87b50a71fc06961498cbbec687b077fec50595dbe14beb2693ea05c3018878685223a22870f9aa43647ac1ca9cc39f6e68fb79b" },
                { "pl", "d11437081375d4675bd7481021a36e883bc94b1ac3c0bab46d7a0d28382a659ef7035bbd852abb35c461011b1308d74b9ec973e0c360a853102a08abb7812db4" },
                { "pt-BR", "f9023383a7f13895a7f2af448b855af00d2e60ffad6ff6d1668ebbe5275d2209301c84608650089412576fef0a2a05f98cd70351e524099808fc9af6fff42467" },
                { "pt-PT", "b7592de06f102010b40bd844bc9db4e3f0a1c42cf1e9131bc9bda03f31460e3e48353aa372eb8f0327d2af6571c2f6607f1b9ae6a20a7cc80c9c82b81d2071b6" },
                { "rm", "fcbeb17dd86d59ba10eb78f07d3ef843d70e0c7bedab3b26eef08664255cf4c9a49d1895b608554d9845bec609233e5cd40925eec8d2064cf4a01c1e66cc0bc6" },
                { "ro", "09c78994af345d305adc42f1f9f42370f72e3308d0e78a8667e8fbde07e56d4bf11270829a409872b12b4d7c5beb76965f141c7b685162f5b0f85100a164524f" },
                { "ru", "a7344390317e968d0e3ef42ddc094a286ddd50a900095bb380702ae2d64aedffd48c9e25c1e9541ad82e5121fd516b6114f14dc3cc538ab6a62a8e7b4c7be9ed" },
                { "sat", "1ff184e1493dc715cd779707c70c338b6661a4e12c21ba2fb5308bc13c956f1c73d7c948c1379b9dde7b629da111d75cadb598474b5188c143c2a1ba7e65243d" },
                { "sc", "4aa1dba219fdb95b4e4b700bacdb8ddec8ea7fe0f0dbac5011d2413dbbc448badb5e175e207ecc30b2fb43beaad94cc1a73a0657d27c64234d6d5536529f58d8" },
                { "sco", "25ecea2fc5dccde2d6af017a876de013f3957dea7622de68a33593a6afd7c20070e769afd1924fe5d88d9bfdc4fe90e870eda1e8209f6b2c2191781a7d3332f9" },
                { "si", "b6486acceca26b2098965e91b80234cbfb55dd72d0bcfdcffb15eea42a03ac7246ec1f99a4ea7091f7fb7e99ea899a71b3b6585be49718e10fe832c550ead6fc" },
                { "sk", "578d66350d57c452d464a0faa84dc9ad12a1edb12abbe54d124fb46015c0992678eaaacaa9c20712dc5400cafbc6462fef317ffb8b2c8988842f8610db00f480" },
                { "skr", "d450c53e44ce097cae4000f6e6358f7b130110f733a3ea11c4db13486c51fefa89a4c0738705bd53873865d54ad504b13066750f8b24549988cb056c0bc35a3c" },
                { "sl", "6a145b0ae5861729414b079089f84dbb064e3cf48072f43c3918cfaf0ef5e2b49f053eaed784c601f2289cb2e0c92864a8a8294bd2a1c00bdecf4f6f8c007a4e" },
                { "son", "e515ec1ffd4fbbdb7c58e927ba66c6a8b6bcb920709838b6a5a374e013a84c61325456487e373e72350b04e88f55a298722aeb10f3c331a9cd201406c45c0a6c" },
                { "sq", "1aaec215ebd7b3899ee4a2ecd5e0ecafad4fd1cbc76328462f332f36cba70dd7f39d31133e52bea6243280e65fb8faf784ab95e64c35e0aabcc0827c5578d37c" },
                { "sr", "1118abb84bc8d1c089cacd86e90f37e8f8ce7c454ac740ae215b158d1be8cba7b12edfbc2330b4263c8b07a7cb3690cab3a2d024617e463e5feb479eb1a5b9c0" },
                { "sv-SE", "f7bc23168020c9f2ace490cc9611a49f8eb149bafb9b17c591bab7f283512c0aeea1edb3eead0c79765154694d9a4872aa4a06ca1137bd02c88159beea28b898" },
                { "szl", "05208b3296e23211959a795b57a6a5a85c11b1b00ab9dde5ded23a52d63bf2248737881e335f405ab91ff8ebaa5b9239fbc91d24a637a6cf2c964f1d9962a4f3" },
                { "ta", "2bc60b6584040fb34e56676aa31b361214dadc09b64a7ee1f0aa9fc27ac792aa281b0f9948630116b0a43ae4627caaec8466b247b309b4240087d7a2cf25ed61" },
                { "te", "cbdbdcc756474ef6f0674125b3a88603b3682da5c11482ca22d4fdaf1877ca0491ea7750b209d10597b5f3911842f323b221db99e551665960f7ab35dcb8c71a" },
                { "tg", "d297b9ee437b721b46a7b93527d638de5311a0bfdfec8fe7ba8975910ebbaa5e448e5a424d79faf74355c7d4dfb95a4d90182757ec6319fd884a8d751612341a" },
                { "th", "b4b55a0e0b76cf9fd2de352c738e36cd493386452eded262621362462ce184f81ab1f8f54bcc74ed3a7b44f84fa125151469b513dce29e88bc3592f5b26bfedb" },
                { "tl", "55d347a97c5ea0335ca01c531ef6d17be8428cc953fb6b776ac10f0f79cdee0fa49b635e535cee3b5efa910aac218d8ba808201ebe550d0fffc878aa8f6f22cb" },
                { "tr", "bfae5695d6736732d85172b5a0ceb5c8248cb2babeb419967a732fde5157e5996384591d122ee1ee056407632f2b947ec829717f0f4f24ecba6964cf55c30234" },
                { "trs", "4ad75e750d88d6b44db1df7edbe3fa71afa983373e0397fbd9b1f10d6e20cfc2e2c6be7cf8b3f66f2f04b7fe95c04f927070c33610cfec40718e84be4dd06a27" },
                { "uk", "05f6f450ea03abddb62b138b1ff24b425d961c7bd25781a5480a94a740ca61a727f4a8c309aec8bd24f933366414c54fbcb2efea35a6a58ff81525cba88ab099" },
                { "ur", "be258daa5f4842620c99ee8f81c33a7c9f56deeea79918b2cf2e89a4fbec9287e623a4a4e4c9238d3455c9e2291eb0f325e085a47d9f45db1090ce1d20840c73" },
                { "uz", "0f992811a79210cbe3939ca60756e414519eb29cbf1754fc4a80304ba8e6f67940506e2d63ddcb823ca6670239a92f320094af458525df469c8c6dc41cb4601f" },
                { "vi", "5f23093f227c4298c8e0f24247742d6f418496a38d7bb00fb53a880db77f79c3a2188f6cc4d77ec32cea5bb5cd01648608206bbc3d754696d6131a56d6761e60" },
                { "xh", "a1c9c50d3368db5bc4675655b3a96222f26dc290edf998580537953e160cd9e24a5e11bd8ff4bb8d35443c237fc22c14cc8e941903896df57e5375bce88db1a7" },
                { "zh-CN", "cd152a80c39863cf42bc81983e055af1aeaab14f6f6d1c00beecda49e7445d4fa8e97cac36e31ae82b87679560dec5f30550d00c50a89bf92697ae891964a945" },
                { "zh-TW", "27928736cba3d1cda783c86c8949e30814056ee602b0406e9430b9c7eaf0cb49813acd61f29183117f94949b6bbbe9567b46f47ef00223f65ffaa00a09ef06d9" }
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
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
            return ["firefox-esr", "firefox-esr-" + languageCode.ToLower()];
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
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
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
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            return [];
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
