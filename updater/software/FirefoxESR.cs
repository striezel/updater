/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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
        private const string knownVersion = "140.9.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/140.9.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "b35736f9ca1f6e5dec39fa2aec815e60310e8596024e05e3bc5e07be83e7114c415e569f042245c07ad6826e4c27f50229ec8aa1ef1ee34d5b69b6b1622a7a69" },
                { "af", "1c005daa4af21539187c296c75582bde166c3503e34bc1eb7ac27822fc52a7b65f803e9e89da2682c2c25b1cf797b3b88dbff9f2f4683a5f1effc76c1188ca78" },
                { "an", "b453ae70876d19ad5fcebe5468780fbc60245a08993e608440043274f68d9213033ffae13fb03709e17e30e59e9f93cacc6b25d84130c7ebc764591e40fe7839" },
                { "ar", "fadd08f1131954015f068f0a7c6a7ab90c64a91271475bb3aead7e70a18a202b5fc273ade1c2e143bebb5f08a97494fd4fcd538b3650e9fb7c2022f7e01cde9e" },
                { "ast", "d78d88de66efb2d9fe522b7b6e7f4b0ab3f4de7b5c4e68a2f42123ed70730ed51681c9cea12e2e75252de7a585e69ba3823c26f99ca8296fd7c2c8d3204f3ff4" },
                { "az", "e93e4f22e026e57ffdea4453c4ec173c12a69315d530f34315173f4dad4710a5bfdef4a5b52f2b12d5781e02fc7e6eafa15f1b6396b2b3b2a7e32bd9d493d090" },
                { "be", "f36e80aeadff478eee84464ef34d4fc4303d29b2805e937233d2e8fa2b49074107964171a6d4a7f321f030910f2e182960d25dfcb13688d35170c3dee72cf615" },
                { "bg", "4ee194ff49cfe5ceb88995ad0ef45390f13412cfb78b750ccd8db835e1783af5ca6b0e7f3bc87ee1c948572ccd35d3a6ce2f71cf261126f4bb4a50141cab6435" },
                { "bn", "4e1d354d24a6baffea032a19df4e40214dd8ea8ae1a4c9693086950bc72daa70fbe11b108d7004bca28744a29dbf430b32af083313bd2f17fad806de2192d5c3" },
                { "br", "8db7ee095ae0af93ea3250be017541f89432c6a3f09ac20ddfdc80eaf0ada65fdca6cf92e507923569759a5d98ca3c9f542b8645f68e41d04330a18e5f614f26" },
                { "bs", "33c2de96fcb03d51f332457e9ba09f6668a16f67aa607970be88ed9ea0267420db6dcbf23940953e5083d7fff09b98841c61e393d8ac617a5950138331b2f88f" },
                { "ca", "9b12cb645b20583ddc59a8b7cd22981cdcc1044bd566a9e5d098de6723587b64c1ff096d756c015133a0d11be1923c9cd8573855f9eca64eb02f2e9630fa12ff" },
                { "cak", "eca36f914e1767776eeb8e505cc334dc1e46dd4de3e6d3a5eb68e3fa15f02735ed71925fd14192650989607bb491c1542559ee5d96a43adb4d37445673b8f5e2" },
                { "cs", "8b05862683c957fb41bd617af93e9b82748d36b0b3c977eef95d18361296ed5117c9d9199df65995135ce1e4758d98393e4ef73c4d0c3ab388cc59e9204ae05f" },
                { "cy", "8f852697c7255cd4633b4efd98b8c1165f8b665fa18240e5273adbf5040bbdc68a8430f72df7c7dd3939b78377904ef80fddb9497e392ba7b5c8ba1b92814217" },
                { "da", "b2dcef212fd0634596ac754208004e9af9d6660b4511960b137dc4a995a724c626978517a0ae63efaec9cdec7d1cbfbff50a6e7e657a55babae8513cab9023d7" },
                { "de", "4a7cf2eaf0a30ac77bdf8251037a07917155a130ace0758d54d5e086873192447f62516ff410a04d35387a8502c222189273f87877d53d5c9efb53f62e21594e" },
                { "dsb", "b10f30e0abddf9ece23b18d79ab6a94b309e0e24b6c0a36f1390b67f97c0162959bdf934c0303a61c479f8234b62e25e7733af854d6f4d0c4c4b7dfdc41885e6" },
                { "el", "39bbf477edd80c3a4edf793c1446dd8f040e424b662de355409ae8a0541b53d3c94632901e1ace30705aec7d891476e08478eab69de4f743ac9d0e2976783aef" },
                { "en-CA", "7965857159b9da18cfc9dddaed44344b720b06d3668d462d0492bb18ef1fe1a7f23e7350c044c0ebd22662b2b4508e09437c50e2660a371a1c1e68207b4c5abf" },
                { "en-GB", "e245c30d81f24a1100aeab7b7099048ab045035a9966d3999e059c1a1617bdf42a3d54e300ed4371afa8e14ca8c7fa63ea84874b150b27d017cf8465994337f7" },
                { "en-US", "6d278859445c3f1abd565e2b4bbc530695059f8c5d1358d2d79f5a56a4c75dad58ddad493de9ccec8b44473cbeacf8ea67571cfc54ec13e419c228b313fda7a9" },
                { "eo", "79a1afb74282cada2a063334e959b6e43071e7825baf30a0987348119f46855a2da47c04067f65b69af7bf3df6b98869e640ad5f89ec178a00f9b350c2c43051" },
                { "es-AR", "b3a1aaf7af04f789a3aa24fdb8ff444194a32635e1456ca19601d735ee3822ed8395a382a5010bb55f25c8bfc2bfe010b1031daacc994d64037addab9ceb4ed0" },
                { "es-CL", "51e5697919059792202831b9013909f6d6d33cda4b9945ce506b280fd2551b5628b07a84e606b22233077e4d6eb309ecc2116aaf9df0783df5f136e80c33a5fe" },
                { "es-ES", "43ee468ea2d3cbd7091ab738aa4738b6bb615b1dfa694a5c6a92b26513237664dae1da7dfd8bf697585914300d970e686ab706c661b84854340f594336b1136e" },
                { "es-MX", "6c7d56cd81dabdd229a9847b24fcde7c16c9d6a557be29ebc530acd3d34ffe01abdfa6cba3d29d62cb0df2428abcc212db422e983755d564f2cecc758282dfc2" },
                { "et", "45962932de652b2ba07bd1d3105dadc0aa8593c87cf8a3a58173ad8fc2a69be068733bd51bc5a80c3e51edb96b607b68836e1b0075372826fe144527370cd5ae" },
                { "eu", "0f9c2bb8566ee9f16f4d8d67ca409c2c01d698bb28f1f63e84398b1b2ff9b27bdfec3403a3284a8aedfb5a97731ae252c85cdbf8ef4183ae600d7456370ffeaa" },
                { "fa", "71950012bf7236a50075c127b67c4ccc1fa08661a1eba829faeaf0846daf2bee22107b363e37b2069430bf3d5110518f2e09a35ba18da5a1d4a79b46445a3e01" },
                { "ff", "f81855f7cb6d21b925f966dbbd83abc0b38ca1435f20944a93a0242355d2dc901d4b595134af5d5107bbbccecaf76e9184142bce9a0ee437c11d189657b5af85" },
                { "fi", "07a184ea945f291d2fa91214a0a9fb9be3befa702e82b5bcb14c6faf2af97b5e5c37e82ff995489850fea21d7089437819f019d86ef684443ba8feec7665e654" },
                { "fr", "7a3dd2c3a543feeeac6826671c4192bd32a2445f0952c60e2ec66c20dce4ef699fc1ea76159192f5932062c7cfd77ed6300e032cd995fda70563b27928fda099" },
                { "fur", "65cdbf77f6c54edd1f378a94c01fb05651815b520d0fb17fd3fe9df3ff5a5bcf9daf5e4e4e4665c829d491fec776e28d553ac7ae814c11daa098ea8e6083ae41" },
                { "fy-NL", "8c86b3d50a1ad9ecf1c8bbf8a97781c9c4611394fb5ce55f02c03de84cf7acb0b78466ed9ff11bc0559167078c812dc42439f37284b9844cd138f19f8c889e1c" },
                { "ga-IE", "881373d9926b042eea5d3805cfc22b4971920f78ed1fd882c0b5d040bcd5e28951f48c136b64e37e7f473c8678ff4ad80de2294a1d4d95739d6a589b4a06a37b" },
                { "gd", "758c7de23925c9cdb041703c3aaf8f0d82937c93318bebd747b0cdf8cb658103d4302f835207da90d858837de20fa80929bd359a40bdd261bee44d7feb5ea11f" },
                { "gl", "5637aee44384639fae221e069ade129e0aac1e4425cf781920f8abd1b6073e0efb7d24add432f0ef09d6b3d81e7d68452c4c09d3d347cdeeac4548dfa8ae01e7" },
                { "gn", "286f2717c49d8cd01df2ab9c964563c7ed0c0e87fc179d50e42af1493fe045e0b77181c5c3e91853a2ab56aa25db4c9de1d4664ce23877da44373dd49955dd35" },
                { "gu-IN", "fdec430f0bbffbdac449b1896f84b88e3ee2405a47895801cefdc19826ca466e4d87adfc8838a5b659d48f1ec7ad984ab5a5202d5cc3b63b51db5d9198e48b35" },
                { "he", "58db07671d7e1b070b813b7fd490cbbc839af1f78930dcdafcfc6de9059948bf028b09f30b8b226ed9763c4e3cd2b1991769fac0ab25f8b85dc1c08086723de5" },
                { "hi-IN", "a9bc8097734495e6f4ce47ac54459420e4b8590e1c2efa78bd02ccf3a82aa39c5448ced5a2293068344e3191db54a4ce7c51411c5f1c03ff6d08330f4c45ee96" },
                { "hr", "38881d079718aae4f719e6b228c529864690a7c5ba3eaf2306abfcecf3d47ebbdb738c31bcd449062aa0083ff8e8f0dd5a3d0f5f1ff57fafec0e6d07a7fb28d7" },
                { "hsb", "2a9afc990327713de6b9db0040307b5794816712024d714b4371639660bad6e80a7364f4acb3cbb9793a4d9a394f206ef06b4c3f7dfd608fca473859278c3945" },
                { "hu", "08d70d5e219e70da84c2d864d8c8fe6da73ab1ef8f781fedf35ea9215b2a452a0feff9404bf11a0f100cee2a62965eea08798d8eb7c9d9c05a3c79a4969b2d89" },
                { "hy-AM", "fb5267d7e5ce521a1a7f9521491eeea5f1205fd572b1b338a047a8d0738252f362219d6c6ff9782c7cd5e4f000a377f3487dd8a5b58080df14a681d630e71e69" },
                { "ia", "52d1fa36980fd218060d3c74b54b12e9b2d0827105ae9f387b7b821b984d49b3757ef8a6c7e0e093687b451e1f96489284169b2e38da1f50a24fac35c3a6fa2f" },
                { "id", "cc084f9f5c37c2560f2d0471b4beacf537a49b600e3be0c19f00307c2193a33c4a6fb1c794f33ae723f0b97af400f79312a5f90de9926e91bfc4fe2f2749766c" },
                { "is", "baf2e363f1ce5ef1cf385b4db22ed7007afadb9502ddfaa355df477324faa33fa71b6d0b5d651d5e7227e27581a70e8b6103ee5f255bb6cd18b959616ffb1a62" },
                { "it", "86de677fbe6867225c12908df1b36fdf45a6184d13ca2911f17e5f7851f8fcd020daa723f0700aead2c4757f29c2e03f77447db7e8d396915788cc0d48af1a7c" },
                { "ja", "fb3935292fe3c84eb9f90db118286f90b686a0b6dbf34fd29b43890bbd21440b2c01d51e4c730714fb1492808e3fdd3c5253ed86ab92f69f566d28dae2d20d99" },
                { "ka", "e17065478e5d194ed88a1dbb5ebe5d598813545c0dceb8b6a6cdc9b7b4d56909b120383a7c1fc9e154ee408b47d8730e3efe5bf72b4d010602a7cf63990cc092" },
                { "kab", "040b0875961c3dabf45ebe414212a9fd4fbd4a566b0abd624f810a124c8e4d45929c40fef0165cb3787d8d93a5fde19ce7c1ff01b3766cf94090bf8ee4fbcea2" },
                { "kk", "239470fbcba80c0ba480f3a7968eedc7e0a8dd6807ce80ed5ba9c1008eabb9f55b5f2b9721caf8a917928e3e2daabaa1478cac475a52c06f1f92a515ffa87303" },
                { "km", "c9bf4f9936395f88f2f7d2e843b1bc5c658ab789dec31f8377be4599c74e05dc1988ef8cba444cb2ccf9a6f414b463c96872cd950b0faa7e4d2770b378c5763d" },
                { "kn", "cfeffee0bffa88134446472a4708be31449d67992a46f1d095348b883407358b231e0be011f6dc04e3ee0234bccb57fb8a6790eede4d02c9681976aa14083dd3" },
                { "ko", "c35f7d8e629122fc648281675a316bbe0bac65b87a462255fa1403092b958aa8d231f0741d07a3fa47bd6f0e84f6f508a2489be2802fe4ca96627b5807bcbc7b" },
                { "lij", "9895db3b1565b6da060910cafdbf6b3e453d1dd75bd76eb6d71c8cadf7fa53e6394aba35e5c9a2f6973dc5fcb67f6c76a0872fd0432595ff753f8681653729c6" },
                { "lt", "56379ec7faf91c32861bf4de3d6ec9e34aa1b878e1e9a4415571f0109387b63b7c0033225bf9df8a1ceb4788633ff6d19d07d8488a92f7a14733fc6ba9afc1b4" },
                { "lv", "77948f078f63726dc3475869f4712e43ae6d1bfdb098fe2bee2c17c8c1d36cd37a9eea3f7f6ebd0804ccaac49601a795341066635b54b09a0c11908d905022a6" },
                { "mk", "b253b13f2660c55c5b44993d7306e95328f3815d5d1913ad574f30fa30087ec55aa6fcf50729a05c5a7898736b703fb66208bddf6a71c7553f2383cf4ae07f12" },
                { "mr", "fd0ea2deee986a06cdc15ed2d5e8859836aae072dc93fd5cdf6408b864c2a3450789a483bf07fc02653fd82ea55ed1bb87ab8584c1e8ec2cd0673143cad23a74" },
                { "ms", "316a3ca6a8dda90d1d3cc1eb9e07780ca772f3e78448a4f212f65f1aa1bcbbae997a1e248355fcb3be5b37fde632ffd513ad220008db8c8fd6b88e572c35d44b" },
                { "my", "4748bf7acc607875ab7981843e2ade0b8ef089ccdae3c62bd3f34001a163fa18bb40a9746f23f3f9cfe2f6e1cb70f077d8a5233c687ba3a10cf0d4a5c278530c" },
                { "nb-NO", "6b0a6562f10c0b6c6a00c622313b369726bb52c1783e2fa78ed2116ddf2f66e845e3aa3562dad85b3ae63b62eba722100da99ed4e31cd9bccba4cee2c0818df9" },
                { "ne-NP", "6edec7b84c1e3e5d62f92086bcbb5ea66f59a45ad314c0b2ed815259975d48c4b2c269036d9d51d848fa3972842fbb2014513bae5cfc00de3e3685f679ca937e" },
                { "nl", "46452762da4c8ff6d7591e34a7c70bfcea376e63c391da3e4c0dfb337e44517d6a440fee1d77753b5ad2888401e3e11763a7ed00ab6f1118a30334e1546f8300" },
                { "nn-NO", "1ca5154b61230e5e76e9aa427ce7d9188fe800522d950414ecace110aeca13b548880df5e138f02f3481a16386b7b95bcfcaa7603125141d7a5a5ca1dec152f4" },
                { "oc", "90e5c309bd0423ecd99e235077d57efd746a82fb1ab20ef5e5291e36dd15e4c647907bc40a47b3232ead03bb6f1fef3a1737c986de0920aaa64d2faf76bc30aa" },
                { "pa-IN", "39d6086672e3f359e70fd6a0bc0a65df1df5cb1d09d68d1e2df28f975515be526563cb7111ccc275c66c318f765afcaa4cf1a75254f630a7b9896d6e974f3163" },
                { "pl", "ef2a00460aa68727762c74fae1f42e1bcfaa9ce83d39861ecd4e03d914ae5a740f364183fada2b38400ffa9cb6f0790a2e40a602602ac6a28de1d9b958a9fdbb" },
                { "pt-BR", "903a38b990fa2c673de62960d4a7f7f2a2c5a91d034a73f66779cb268f62cba8d3f8c724f177b8c126ae3f964832b159d17f702accdfab9134bd592701eaec00" },
                { "pt-PT", "dc757e0b981ce422dc03678ab84cd89ca497bd99d0ac491526318c09124bf229d8042696f1fde23dc05c7dcfaa89b774e26b9c05be7f5f564c08489aaa728f00" },
                { "rm", "fee3ae62b769eb709c5a446867185a3a37eddd7f8df833596ad8c37b759ef883232fdaf73ebe14646dc46e4557540a537b20e7a413c24de651e90b78b1f4e613" },
                { "ro", "3893acbb08cd7ca9687e094096f6ff0feaf599ab60523628f8d12e325d7c19d4a866b1aad99f12e0f406feed794470a022d8c87a870ee75196e009044ce86c6e" },
                { "ru", "2836257634fc0ee3a377bf144b646120e497dfbab2057e9e93106153278df999052d684e47f0abdbaeade86ef43947b3a74f26d02338692dc81122efbe557d7f" },
                { "sat", "5519575b97c1ccfe90cbe1f940a62ae4a574c0817ba27097db7fd97a16c7ea9f088abe03ec26a9674637925d6ee23616ff06b7b513eda50cf4605d71f9160488" },
                { "sc", "6628c431d5bfcfddbe668a31846b7a63ee7e3b1d530c466ce991de8bbacfabcbce2a3a264e36c0346e7545359c509a1a207cbc1c4ac0cf1ec6797dac0ee0640d" },
                { "sco", "6d4337ba055e609b18d7129296869b7ef6aaac9e04b32b1b30a417f2be70270591e324f84ffb777c5fcec59b48c91d213c28739c0a5e4ecee3e10fa7683620eb" },
                { "si", "f7ff92227c2f380c891506ee5aa6ed4fbc412b260db7cd0c4c642f8d40cf968739091d049cf1c70147f8b6a5991e46c4efe2a54ac721796fd4369ef9abad5d35" },
                { "sk", "0cb17e3203183554c32c37f65292b8f6434d16e2c95301f45c45374a545e8b719b78599f04ed148ed06db47bc5d0f4ce503d87bdbf6a2c060b33e0aeaa04d014" },
                { "skr", "d4c67e9708c306fec68d558df4dcbd9cec3c0fa193ce243d79dcf87e7e3cdff4974420f8e0c0e66c061673938a91643f595acd115e7e405d95f4d5601a6826af" },
                { "sl", "764fe4a438694711d9184f8ec446bccac36a024ec4076b84bf3223f4ebd9c3289fdc6075054ec78755e987fed0fa8b60d6ec81dc7e61b1eda084c634f09ced5e" },
                { "son", "0802714c898a8cc019dfce498c901e12f4af80643da47a45be3ac07cf0e6a2ff26dfc6c6aeacaedd7d72d927ebf0f5d0a4ef49e1639964c938528ba3c5170e40" },
                { "sq", "1e73f11f80038dbda700fb93b1552f9c69023d2b8e4ff2536e14b0bd54473ef178fab6d8fc7018451392c9f52cd90d9638f976b97479ca14c6fdc14e7aca66de" },
                { "sr", "4447b63d433180d6a95dd6bec3509956145f5d8776662b5f9c7380076f0505f21d9533effae1429a3f7e6b25b3107049551a7df0f89fc8114606130af849e1f1" },
                { "sv-SE", "d7eed677b6279be39d07526dcbe0300d2904a3704e0f15ad04f925360206c1d49099e5d5ee2815b742e0fc8b8976a0869aaf90df636cf87d14bdf6d729f5bc07" },
                { "szl", "38247ea42441e1f6c213842ccfc083c6dea2661345f5e0464547c98e5421b9a2d3b370bcf7e0fd10a3fa218a132328798169b3a8720a4f1c3d0dfba9ef81bc9c" },
                { "ta", "f75ef453e977e78eb0e79218419b8d3b7c0638a75f0582405cc53e16ed40d9bb85509f4f5a14ea57a08da5e7ffcf286d22ca59399f3bef230988bf60d6b3afb6" },
                { "te", "588ae81c76d54edb352e06b476b4db97b39f80f4422b1d14b85c834c64abe3ab964258954759a434a2198c32397a784dd2c58ec9faaf304fcd6585fde67bb6d4" },
                { "tg", "8d07c3ef14ff0c6da3d9edf313fe80f71bba23ee4c929c02d1508e89cc148b739fd685a29584e185298f646d48084c9392f4f4baec97820725f9941206011ce4" },
                { "th", "1a21eb829a5ab9766c674bfabd2c7213cf86bc0803dc89d703eae67eab1658edae93f8ab50bc2f6b6aa3f9fdc71ab00f5479a23ae7638d437c69f4f0b49a1882" },
                { "tl", "b6065ce4adcbab1ca9590922c023369a196f1c4e1efb88884e2233bc16b1bd003c348b69e85de40c03c90bf813c13a2904d7d1cb94477c82b3214e74b5c22a28" },
                { "tr", "aad46968ed7118f63562703f745ff22953fd60be4fd42bf5be99c01b2e316da6fc27476d5500ddc82b087ebbeb1191c2925abdc17c99b0eaccb3e5dbc4cf46dd" },
                { "trs", "9fbbacc90c1340012d8f3c883a0b16f3b0c1ed7e20f4c3a667a3b352d28c34de72ed1914827b4171d4b3c4b55ed120490168406a865a962eca0971f7dbd9b578" },
                { "uk", "74a1d3c44621e58b69a8d8cf492843f786065ea2d548a30933bd3d4b325991f57b1e9c1f8776f1715b807f14e55e0f29563a1c10e71eba98374aa32d5daa8f2f" },
                { "ur", "548b0174b137b9f34865ce399eb912953097d0994fdb2ca8f5c86218a8f1db21f9242a9e6ed67118ccce6478e43cbb6556ab8cf0fb1ac343991562c2b26492a1" },
                { "uz", "21b1223819cb807de95d2fa0680f5466a76abca5690d39ec68dd904f3c0529ce558aef4f02b0894d9916ae33079e04743617747d4898ddd518bc3f3aa4049140" },
                { "vi", "b37f63bf368d41a4cbd5bb474e7316c1cf4743d412b18441d8934eb5bbd4a6f8a7e09c6b2b9c51f5ebbaccb02a260f36231cbdc5fa5388cd2d0ee91dfbf71fb4" },
                { "xh", "677d5bfc1a3bffe840b18f75b8ec267f4adfedc1c08aa347b1a26cceb98bced627b5c80c3e52f7d9fc49aa6cdfa84bb2273e4c8397201d2ffd133c2b0acb4db6" },
                { "zh-CN", "917b5ac4acde5b736f8f7fc336fe7c9943866b4c47f55fdb603387f49b32c724b9a46ad52e2c42759ec444e99da87e8919d20cefd446587e5af9dedb7bf8b7a0" },
                { "zh-TW", "f50e1a8f6a55ccdca6f5a038f31d1e34985a08c1aa45d849785a9fe72e737efbf31fa1bffb193d760a6571b7764f9eca93123ed4573a6140bf84d7b904cab40b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.9.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "bec8e0ee053e9f172158b6d543ae99c7486432476c0cb1ab623f9831c0d1d2e5eeb0c7e127588ddb39355d06a2779116419caa7970736737e9ed3f5baaeb5929" },
                { "af", "9600cae696806e747b4040ed7abe1043db2ba1baac113ad10fc0f55ae7e548fc1c71266730e1d122a6c55e3944b98012596a3dd8db0d5293f43460a4fda15f8f" },
                { "an", "a264e5e8649fbc99ba004864e7490c07721c18fecfb1bf27ffe2efc1a52f6561dd2312ddbcf2aa740698d03c4efe9463bfef8a5cfe7e7e20370c7078ee25e019" },
                { "ar", "aca9c184d8b6bf91672bb7dc8da7ce2819967cb913976f08902556d7edb7915fbcd248bb0508f8a7c3a219cb1533802d1111b1205d023c4440e8683f83052f62" },
                { "ast", "bb18f4dd8d7267f533c1399646d516b0bef88b046c1a3e0acbe0fcf42414847d6565a61ac4af1e12ac9f5eaf399194be1f96b6472ccc0cd297acc2bebab6a4bd" },
                { "az", "b5c6e58dd2d28e5955e88c270f01fdf0fb92460b8465d91809c6004728d050cf1af9b29f6474455d1d955ce6c3c9029390bfffa6157d1ba10de30eb5f2db6926" },
                { "be", "cfd28e3612d9cb08cdbfe7f33d7a8bba0f94c1051ba95ee9ca6b6fe4999df041a5e0ba8036d413c06b3d415ee479b2995eafd45dd4b77dedbf12529835ebcb2d" },
                { "bg", "825c7f76175e5a5271ea093bbcb8c9d5d5bb197324c4bcd2039e7f74e41e25c41c6501af1fdd65a18640d67b67f52881b2da3967da5495401819cae49d2d84b1" },
                { "bn", "d632b4219797fdbb4b6a30d57f3e2d5934499c804bf2a6186ca0bb41fc15495b15f239dbb2e1dc661d0bb7e1f4807253e178fd1dbb898e5e7c9623c2c3a9ea6e" },
                { "br", "2993e13689b5ec8517027316ff0ae2e9837cc6a03266f956fe3ce5f925fbf9102d47b554eeaf0b42e66977c3f34b7c353dc6d765387fe99cdc8c181cdab491e8" },
                { "bs", "3677016c5c3a2c8f1e4fb4475278fca30f631787bde28e73f4d15d87255fbedcaff18c67729b34775b606f2b1942b751b2f3ce8aae437374c8a623e57ffd65eb" },
                { "ca", "056e13da55919deaf6db2a7f86f80caf259ee4100c4f1d4bb774da9a439330702f67af5995d115819ea6b5b85f36109e323f916819d030655cb23426f9994db1" },
                { "cak", "8ac8d38f22bde4236e02722e9aed921a1355fca959f4b2485a342269502723f7d538bf14acf7076816c7c82ac8155ace2417f43d2fb4ee5395dd37c5ad704215" },
                { "cs", "eefda4cf5fca502d68b5c04c47c853382959e655386074331d5f0cea3343aee303af03de1f2c7109a3966a5827c09c5c487173fade66b16726f7220f630bda8f" },
                { "cy", "a87adca0821cb0070c6a6f973a886917102862d6373b260d32b4f948448982573eb18307919b33c9602d607b778c6d6f675a2abb6cf3044559626e5b3dd1e9b1" },
                { "da", "c020710f1282084dec747cdbfa8fb2c0fc20cb607337f5d31fdacd64bf91ace6200f069f52ea3a9cee08a146974d177461807f677f1344b08e99c1694acf8250" },
                { "de", "1155534a7c9bf161d1679a49a7820a1e57a9632ac46f3ce232eb5cefae854055c12c46aefdcd8f3b1c17399c6b4fa688a8a39945003c236112f6ee972875db7a" },
                { "dsb", "00a0bb2777a7765cade79c6fa59ec5fbd4e945f509d19a81d9d3f7f2694311139463526772123021434f606063ab99e81de73cdf5c2b0f0b8f2dddf9dd00e479" },
                { "el", "dd6b53995449cda61cd1f13b7d6f8035d19eef45d6f592193e2171db1b00f342f5f24499769cc477e64bee5b471dbf987df48e1397f28e6cd1a40ad1e396feeb" },
                { "en-CA", "f2e5e5ba66fb6c29f4c9c1a22fb644eb68e946dc2ca2dcc015354176c0b3ac361e146b1c31138a789d552b6592f3f7a7b9c07828c696e6888351ef01e0b2e234" },
                { "en-GB", "a6f6584630d73ba47f366ec885d6999bf6c16757e2ea2959de58dd9b58fc2e276e48448b2a9d1d06307259aafcf1a405d326b4f9edd9a99876d849a6c07b632d" },
                { "en-US", "a2e434717870e059b90eb96ec755772ed1b088e4a5d70011e75f1a2738857eaffc38f08403dc47ad69821e67430085ebc45916a7f1d8be0fc443153c43a045c8" },
                { "eo", "d045fc7aa7771a24ea92549a604fffb9a4754c0c02955fccbfaa30156fe2396610bad0e11f7110e2789713f412f8bd9cf6646e9a86557e6f5d274e9fb731e3c1" },
                { "es-AR", "100df4bc721e6ed5672a98ac2047b3bde2d14700ae2134ecae3587b3d88f35650b505f89710f6d407d985595ad9a4174cdb24cde53ee3b75718c8b082bc8ce88" },
                { "es-CL", "107659543829d2b5166fd28286eef538df536ee9d47851c121bf675535fe483efe6a89f8fdafd5dff17d61f86027cd93b4a8157585d18e65aca40a15de95c7e3" },
                { "es-ES", "e40c471e931b2779fdb41d2fed0c5b60c179a01766e563d7edd8c5d908b24d853e02f4b1d08975bc2b9143154cf987b8754fe1d2573dbe172bf0ecd53e87b394" },
                { "es-MX", "e1eb8eccf68c7006310f022298048c1254247e1a5ecdfa3b0f20df99b226c2ea7a7da6e0d56ae296bd5f4a4f817cf92f217892fd1a35229c9df1868b2e3eadc1" },
                { "et", "1819a0a33ba40f127938bb67d29cb49a8303ff048d000106d1c47942334bf689f0a1297e9c91604250b25fda0f82e54a68ee3f4160ede43c497dce6836eb512c" },
                { "eu", "ff5c1e103ef9f3bc6173c538cfa6a64fa54bb9c53f0c8b2953352850a5a82e1afe28c7581ae21c30e304405d3f33f40b4314faace89a6d3776de4d180da5f313" },
                { "fa", "517b6df2df0e43eadcff61cc6eae2c4593e86fc1ebbcdaac166a46a8ff1a6ca2fd94f115a8cc67f1cf06c4f32d0ed624911caa8f9555e6840c49ee8f19631312" },
                { "ff", "5647d570e3f3ceca71ad940d173e20371402311f4d26d01f8dd6ff833fa1f9c2b5b8338dfbffcae79fab2b5e9ac47372b782ebe77831d65763a154ce9b3e0f4b" },
                { "fi", "964f133835f80c3a508d2af1ae24cd7ead88043d3e1380f85b40ddb8ea9a1059db720089f237c62c53b9bf62451671472d76d5b8b1ddd5d6e59d16cdbdbd1253" },
                { "fr", "f1b95a125204b44754cf911f0a8fc0c4fae631a7cc8ad4890cd628dfeeba2845af06bf04242d6a6fae01f2134ddd76b2ae40be756818c8acff37b9a865203a7e" },
                { "fur", "5e136e838373a9235021ea17f55aa744a15f842847f5a10a0d3116de5c19e4803d62eabec81995f9baf27f89c3db82d285d6c42e39a3232bb81778c420179f35" },
                { "fy-NL", "4c43bec944e302537d6d9a2233f04041f17a779de231c4919fc92e44eb7597316be027db431ef47cf316b247d52abac7de8f525169f3a85d90013ffc0d12fe1c" },
                { "ga-IE", "9827981459ff196f80d6a1e59a5829d5467d8b285977c342eb5ee90df5e975f1af6bd33fe64eefbcadbe705a9db4f2680b8b2da6b33eca4a557c61409d7d1c2e" },
                { "gd", "8e0eedf064f7df6011156184f4104868a6de9315b00d46e7d6f440dc2307e3b661b6060771eec19cc3bd32fde2cf6f7a620ed3af44a18adcaaec712c84fffc9a" },
                { "gl", "a2ccfc48bb297c6dd3988daea23897a92cda724820ea40bac55e92aaf9fe2d574adb43a2f3ebee7ade03f013d4fd7ed7d337b3940f2ca3d83b96141fc1d00923" },
                { "gn", "2e4641b305b37288ae0fd2bcabad56aed1ebdf3cae28dab46d8a22d5973ebda23932148c1d5cd5ff66db926a7a59055cbbce11a796a2043df82ed11c783f7e4c" },
                { "gu-IN", "1b2f7dad81a6b310bff522b961068d92a9398ef83ab5ab56d01b1aeef34f979a1249ea86758c8a28542a460846e433520527bab3a9ee76adf96c52c4888a1f1f" },
                { "he", "721095bb4bea19f163cf30114b2c7de05003ed0ac5ee783757c5405ab6f16d2e168f87fba1ddf263b05a42912f9da024f60c664924733335ddae5310eaaa72f9" },
                { "hi-IN", "9b1423e23ee0b1eaafd0edcd569886e80e1d779320f5420c7aebe40d3c507413769e8dbfb0e492d7ecebe4797a2caa07522f4df5cfbcc915f55b7d12448db862" },
                { "hr", "5a00afb5ebec5fd4ddc82e61b237282893c151140722876c681a57a8eac6d4c844ba25d00907359afd3f3dbe6d3bfae5ecb1cbfd1b97a759a1b14f7532865443" },
                { "hsb", "8b19f48f5ae1bfa7fabaf7a56692c478e55b3c017e041f8a947232a0f1958001a02a60fa58a6fc0f9fc739613b4f8ad38055ba1fc2d25629234a28662158123a" },
                { "hu", "6311f4d4ceee7c56234176ee4c79d94a17f11b41cd5cf90e542271c8e0df020613ab2b82bfabfe8377295cb31319c7b0f78708838371c443ea2d2fb4e15b4940" },
                { "hy-AM", "acb04f594df402195ef14c396f401ba810954e89736040476d081d6d4fa307f17c41a0b7f924e3abce855d692af070d6e4ef0b07a58dc94b72ee8b4a9719b6a3" },
                { "ia", "0620ef89886d79ca082b380f1da1c9319be396e33b5d61146c295fe9a8ece24d144b70b956132f2a53d31ff892039f187e6babcea5355e2dddd4a6dfcdd6b389" },
                { "id", "1f6ee8df71e69095b5c833365fa23b7a0491000fb87b9958385da80cdf09edb0d7749df16b54b46377ff09bc9192d87bc66bdf8f9f0cb084525a3f3640d52b29" },
                { "is", "e2c652a7eef991c101b7cc4ec44f18eb683e7c27a3e01c81168fc81c8cbdec4b55bbe34f79fbe0129b672fefc207fe9787c8ca28506f43b52d31d8d07b790f72" },
                { "it", "80014c82dea4cbcfe9d47b872a4e1d2852a2fcb3ae4abf4bc6dbe40129602cfdcfae47c1dbf92143644b4a44ac0b816b7be240f4c6c64455d65c922c0d50ce22" },
                { "ja", "154f22350eb86a1a05ca2d415279594c81bdb10694ff33742fc7a96a0b985d1bf65f5e5ed5f22b73b334334f8e5a472c0ba8927ff681ff9b4950957a92866a16" },
                { "ka", "b2a1a1a3e3fb5ce942226d44ef9850ced7a8982d994142465c8b8f5e49a52fef69950951cd7e26f1d3e59f37425ad9b32c6f11df6698e10920a3d34057dc1ee3" },
                { "kab", "50abc529eaa7e767355cdda8fd04d0b62c3be701fbec0067c3449314b15ef4ac58d1e2acffc6c4e57ec7593d83fcb455f8936c71faabff7ee23ba7277fc2b661" },
                { "kk", "963770e29c16c44d37c9a6d35fbb5a460738d907a156b52e04fee0a03e244df09a115a59c7a1ccd1d9bf4a9159ac8e90a7c0c5addea638f24e3d64f79a43604a" },
                { "km", "e7e891f1876e6461b03f733aadecfddfa1d3fd1baee0c90d5337a021bc5a1a03eaf2d98a08d146d4219002e79d087445a045e6c70aa5da0be1d03f8459bef6c2" },
                { "kn", "9590cf36b997c64403507703c8e273217e913fba8b88e94e47154d341c724231e13f2158cc246b7b2a220636a9f708b8ca90e78ddc251084aebe3198553444f1" },
                { "ko", "ed879141a24f11cb19b639cf4eb21325a4db413790ade1bd00be3dd5791e98dccc31466ce3a9dd436ecb2de55197563657693f60f6ae559a10a110c6accb14f5" },
                { "lij", "bf150c5ac71014c08a284565f8939d44456ee45e16a822398c9c5750de338ee075d190bfd1dd2b34bbe005096d9a0623045538d436aae9bb7a8ca9b321a41ce5" },
                { "lt", "193aa3b358e1513a0b492d29496d37abe616153805a188b664671e87f8185777305fa5092ab84fc97ffcb5f5dd11acd5ee54026b4ff97790b4b1567fdd06a9df" },
                { "lv", "7ddce63835625599ab599fd3974ab2b418d0029e329d8e0d7b1e72ac0a9bffc386b7f9b98374c707931886530f79b900c9f2f3157dec3a14369c766d038fb44d" },
                { "mk", "a50de27eefecaacd47e64572fa73e2e30fc7a4a5029a8a31e0ced07f169c6dafe45a131a78a08cae4b9ebde2a7c0272968b8bb31024306bcbc5d0fd680ecb609" },
                { "mr", "c479ae4106628f279e13a5b03ecebf58a9226863d635d5e26ed7e7cc2be6093104a0b0dda0150d47bb0a596b8bb23a74bddd2b0765b0f0f16549a7b55fc03742" },
                { "ms", "ba12fa9bdb27e82639801ecc13021487cdf06ef2d598d4e514fc05ca4ebf0117993224c8874b5d78fe6726457c1d5f8e6eba54014a750bcfa799b1ab78dcd25d" },
                { "my", "338fad8752a58c713f5a2e97868ae7fe5ecfb95301ca8d540031b073aafeda6f100c8c2c755741dbfa86800b63400ed88c34d4a4de6ac9c90d3f6f5879302f72" },
                { "nb-NO", "40d76e2d8740e3f4a21054fdd7a2ff2a65526f9570cd21a60ab1de9f4d8473171626a98a5e7030361315661d83e73a7a7767477052db0798548a53713e0e9a03" },
                { "ne-NP", "234c10e12b0a8e00d8ba4fe5262fb55a89d30cb39f04eb15338b88fb1be21614ed79d346ddf56092f552c7c19a83c90d8755dd33e40963d5c48253761cad7b75" },
                { "nl", "72560a7b98ed702f031095d52c95e28f48bde3b51a366dea9473c86f69b6d447c034ad5ab6d1e3f3696762b380740d355ddc294f0f11758501a21c89c2c08e85" },
                { "nn-NO", "dcc670f38084fa8adc59d68693a339a7df9f2dc87d765b6d57a0ca3d79cc539d1960b0f78109e3edb229dc0e9e8a5a3f418622bee3fb65c6365d8cb74d0ffcd5" },
                { "oc", "7f6ce122ec068a008dcafeb78b90dcd66f8c7fc9de5bcfd17d41b23acc6f952b581afa9f1e9defea1b3bea29f99db9805e59251b09a56798e452c62882c01061" },
                { "pa-IN", "ff6686aa7f17fa00f3c7047b72375a132ef1312840087e409bcfde0a915b6826a55f0640505427f8adc12185107ccc9390ad0506d68a120e980f9bf43ab37d4b" },
                { "pl", "b573406379eb9c7c261128486a7505ac8ee50ff1be0efbd79014f7d6ce1e64cdc1d2f78a059ab4fabdeb9b1e8bc19ddc9305c25a87cd6ffef2d5e06e74321a47" },
                { "pt-BR", "38b3d1f4e4ca5f5313e68a93cd3a54861b4d4a4f8c35f23a1af9f0bad2b70ccbeaa6225b37cd50709f277527c8e8d01afa5d4719e99b511139fe21afcd74136d" },
                { "pt-PT", "3c03ecbdfac225c8b55b103135b95d241dc2fc32b9e5adced9816812b71fb0b54301d6bf86943efca4cc35d543ccb40bad366999da06c19951d469992f98cbc1" },
                { "rm", "b7d7d3d772834c86ff7e02262c55ff6842fa372c480cd2b67e48712957eb6d57a59ad99e8c0dac8ebda32b503297e7c7629ea0529c8340756e6602a12bb5e19f" },
                { "ro", "832a37f12986df4e74d9ac10926fcedbbf8804839a8b627ca11fd387da7037727ada19f7ff2a63827218d6100e9da708e132546681a76a19364a62502e2bbe4b" },
                { "ru", "a2a6b10b5c0ed89679692609725578ace57ab336e5b07c77466bd04819d21f3e34caa8d94e146da382e28079af20c38e64d25b5660d5fa818f685b99da3250d6" },
                { "sat", "d0d28db6ae3902cead6f0304ee906ef5ed914d3374c1ba4320c3bbc2c4048043d107c662bbbaa5ba666987fa0fcefe2db5faf5c26cdbc2c0860cc28632c78db8" },
                { "sc", "3e543b435d7ed2dd7295e5c1e96c47312b6d9dd6f11e5567ce7f793feaf09b467fea2742ef2b983884934548cae3f7230a07f1fad5d227c66879a90c8c342392" },
                { "sco", "c116a04ecf2a83dbcd09107ffe83068bcb70d7b4ae7ec44b6bb4e292749340d6b76cc11a1c104ade7626a06188ec1e185ed09c9cd0a02fc9cd856ff188d4081e" },
                { "si", "4264f51ad76532cb61e9f5faa3830372e3c95121a9b96c2917b3c95e4348d11aec41096208f87fe17f5b613d806686203ef05ba5a5fc63b5a331c74987029b5a" },
                { "sk", "e390f9d9fb67b4c12ba2cf25226880e6ad7f55ac64384fbb0e3d79704a06e1f78cd2bdc38cccbe01461ac72ed3ac5a45b4ff5b8ca98fec925f7c25bdeb263036" },
                { "skr", "1e91cbc779d5bc59446fde54a5f4d80b6bc0eae0115f76b707143c7df1d5798ab511a2aace218f68a3ba8a6ac86b8db68e62ec164e857a3f572354c347ee204d" },
                { "sl", "8092bacd896e98d03132dcb10c2806b41babbc44c685b9d0fdeaa733d004a91dfb497f8cbdb0e692fbe924d325e9ebc7d3f7d9d5d49e3260be0a6dc3a0c09c2c" },
                { "son", "c9eda9a7653dd9c66cab64c747526cec7ebda2e0f80c9add455940b4e608c38250f1ec81a8360666ea5e8098de31cb2fd0beb664a64b2edece9214d2f8de528b" },
                { "sq", "4ce923473a8d6d464410b1048d313c716ea347f4ff6c163dcfa8dbc83863f47eb5b364f63b00aacb0cc2c0477b4e8a0f2110e13c02e3bac09f12c40e91486e0d" },
                { "sr", "8cbcccf301bcfee04b62783bc4dba7e85ad1cd421c22472bb09d7cfdd9d72045098fae6a36e6e4f3102fca8629c7cae8b1606b7c9d67f8571568574b40384d0f" },
                { "sv-SE", "101b7fba277c98cd6e64ca94c4ecdb3cf6fb222a87b2d19cb5407f8766da54b9ff6a8ff44a41232dc61d29e765dcbc650ac6bcc7d47e0b43593e0db79cee9088" },
                { "szl", "bf1f477bb08b96860a8df97017040a6a36900e4810f398d85aa43ae8b83e6d0672d6080186d0c96d0ef9748376a051460542d4f15e1c8ebcd681ae1d9550929a" },
                { "ta", "e4361ad059941237a320ac65a3ce95a06874f0aea25417bd7fa3fe14cd26134e77bb3157eca1f9792f56b04477355c648c3b6ad4266718ec2dace6f6a2f0d600" },
                { "te", "4f2a7dcd77b9571485361401d76f6ed93588c523e150bef28edcb907c4d36230fe9ac896d0f5bc47dca39b844f0f1df2f3f781552b863558450cf2c3b4a69514" },
                { "tg", "0997f14f8ef85486d2271c9f2fae7a24bf9176f44962f2a6a55ec47b9526ebb3080c8d857a588988ebaea986f11654fc4dfd9c2436d499ed494eaa5b3eead796" },
                { "th", "9326f527d68190a87efc43c2ccf87a3b0606f4e248c15ea54883d53348f03815e2a5d46c8faa54bab6a39afa78e57db171ee6ccba0eb3d8015b58a142f4b06f2" },
                { "tl", "b287c144a3c5d1f7af7eb0c8ae37ae8c0a8430d4bfc6107fc65c2d322063af92fac661601a32889d3950bb79324b23e97ea7924e981f74cfb41ec67f3715cf98" },
                { "tr", "a80d2a5bf9c1a76f14dc11d1110c8941bfc56240cab6010a8ad9ed694986e11979fa65044446043a5978826b3ad72947b61e2cd103d38b666234df414486480c" },
                { "trs", "7e95274fb82bea44fe72c2e1f1ebdc8df9cb98fadea14fd501961088850848818f149907435bf27e2ddf852029fbac804388f4356d0cb27292998cb9a02497de" },
                { "uk", "ca77d42ca92d1902528d70569dcbcf009dc0ce09ea1e7aaa236dfd226d9792142e0ff677e696f06845c6f31f2baf9e39865eec49d965b386bb4758f9c409abd1" },
                { "ur", "14427bd8f98e1a970b46c01c09845e4639cc7efea1a66676c55798855c8a933c2c3094a4c6f10cc331321ffc92d20f149499dd9b43287e081645e3ab46927e4b" },
                { "uz", "90ca6586569a46f32af3e6c0df51388f071847ce37d37207ab341ec5e2f6095644500629d73b1c4b57fe592b0a6be7b5ff2ad7b65056dcbad78284469e87b02b" },
                { "vi", "0a2ecfd492f52abec5e7de17b012f2c8bd069eb3e3f3006a53828c331508792983d167f35be79f5bd32e266571ff88ffbfc3ce412777def4ca6632ce7b6f92f4" },
                { "xh", "785c5040118403d7aea0208d556d094890dc277712e677e73243215ae06b54db3640e104e7d45d3efd8dae9facc59d325a1b5f57adc101dbb2868f8468cb94b1" },
                { "zh-CN", "ef4b0b72d93b201611cc7b61e7cdcee741f6bd3edcf074dbbd0bd4ba9d1317f02c5d93f96d83385847eb6f63d529d651192aac55da415434b3b62400f12f0f70" },
                { "zh-TW", "e434aba56c4abf3fa8eebbbc864e8496477e33299443d6ae129fe93c0d56538bf800f3cd8ff5e185e9a131fcec2d99891db36bc0a54e4b9d0680794aa6a43d7c" }
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
