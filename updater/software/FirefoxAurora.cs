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
        private const string currentVersion = "148.0b13";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            // https://ftp.mozilla.org/pub/devedition/releases/148.0b13/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "454ece71d55db0c5ddff1d4120de59150dc9677f1e06fb7a2e19871a9ef77035bd6e123b7a98463be4d2f11f1dac05c4b111c5da36b2d5eacd65d28374f755e3" },
                { "af", "b870008e12c1dbfb1e1f27f96b7acc820974092c675433cd0ec00433af1feaeaf88cf58ff63e014d6396fc6285ecc2f7e328cf9b7143609646dff55390e1eaad" },
                { "an", "6324f977631886ea73d387f32a473a67812e27cd11d2f598eeab405c06b1529598a8c21093f831f46cefe925725562fd10c78e3682f2c95f60bf36cf46c9f591" },
                { "ar", "06e202de281e926f9cd79f7a982d43297a457b3b04f91c08ee8ec2e0f4a52a3ef03fb1b12a747bc6b13cd89e97f4d8608575def738d6258631ef67d2579acb51" },
                { "ast", "004baf406a2d4897770a625baa13dc4e2bf69abd98bb4dfd92966ca57ad31ca621ca96be89473a312822a51d729d901b23c975fb58b63c380069ff456fa903b1" },
                { "az", "01ee9e40a0c018eb435d3da971bd45401bd23502da3c1b0915ad0226f4b4998e6abad92eed05b9400bb5dce6fd346a2e776e707a59ef40ec788b835b68a2f6ce" },
                { "be", "90d690ea160a5f2e1dcf87b4f7e27db71695e2fb91b07ca414e146e1cc6246d388de80a6ceb4cf1a0a836b7d493707d55985f2e6f8cd36775587b1ac360868fa" },
                { "bg", "af23d788184cd38241f65e330fbc26c42bb893f1d4ffbca1bae7556a106b05ac5c948b3baff9063d16ee216c7c518dd033fa6cc66e58c7f306ede83b149c53fd" },
                { "bn", "f1fcac69eca9aa5c362db5a5b663a7f591cc03ebb8024d9ed17722a7649429213d41a0ade67e3b3e721a721e9e39511a6b6bfe2fa7e948f035b03386340a7f78" },
                { "br", "26ce3c97b5745fff44529075fb77a177d2e840bb2d83c4ddf22c385c52469fa22d02e88f27f1227c74e100c62899122d3fc266f490f21ae5a673cdcbe421d277" },
                { "bs", "ff8238485ccf545daac5d987cfc3bf9b5520d3e2ae744ed0dada36ab4da14c488a59f0f87d9fdc1c66248f13e658f92259162ddc262e8f697d4b7a4566c61619" },
                { "ca", "6b96c55f0379de7ad2bb2e9d2bf9f0a67d325001d53a968a5c13afef2bfb97d58eacbc8f32b1f95ad775a3a80d1b3ff32d0aec8a961d66f93278f02139560b5e" },
                { "cak", "8bb33401ad1bde39b64b7634b220a93b10af25ac6866a274ad947c57915ab8957ea4625488349223ab10b7b5dec576d455e986c2d1a176093ada10a4386f2875" },
                { "cs", "406c9496223b1d5e0437789d1c87318256d057d367b81d0ef8b8e80c0aecf638be1067dab76fe07910e218fa744dc186eacfc9a688f8a7ed9ddc0ff62d8373e7" },
                { "cy", "0c4323f096c3e9b14b899060a5ec703d7d2175b52a64b6c74b2b52a552c07fb30e38464ed60e847b0b9aa4f3b0cd27f27f2d430a6c14f00804947464ac7c11b0" },
                { "da", "b51704c2bf17e1fd2875f995f80597d7d253823973db4d196904b771b2ae90402fe27e25e6ecc8c5e648f5aa404804ff230c986ddb5d30cdb037e854b04de851" },
                { "de", "d2f44eae120f2660b87a6a37086d5ba7caec680c6989fad01c9c9f08c5457f9bb3bf632b6ecc0258cc0151b23e7283be05a843246e0ff12eb08d7b8599436cdd" },
                { "dsb", "df9702b44a2a6cf92c43b9d109368328c8d50ba13283f9af5486e97c017d113fb3628562d642194c6c15cb88a91fe2602efaa80dd6e43187d3aab863cd47665a" },
                { "el", "5098a968b18a087a336e794198b638412a953bbf10c8da98e170319d43a2b37c80a454f0d11a47d7b5a3ff775dab9ca1688d40dfe3c39626dc27763f5de5717c" },
                { "en-CA", "bca3e86dceffb6c78acd2427fa817b9ef0608f02efde24734f4c7e9e040e48e915fac019a2ff858878c635134db020791ef955ae7fdbae74bcec59eab1178e34" },
                { "en-GB", "17e7ffcfc53eaa89f22a8e091226fbc93a2b264149dd3207d3d33e4333f6e7b038e7722a9d483031d3e4869bd3af2e4a1d09fc87767a6e808692ba897f40e865" },
                { "en-US", "5eaafffff9e26ef0e5474fe1cdd7c24c46fe6ff61c40d054014d08ef761051621dbefc669c866d098e38244083d3c97051b0a63fcb91703c42cba6a77cc47fa0" },
                { "eo", "440a246c0a14d0adb74d59368fdad7229cb262f28828cb3035a2840934ee9d3455f08b38814e5c5d994fd9b9bd97e5032a579e5284500ef358f9737ce8ae0078" },
                { "es-AR", "66ccf1b2ca43a8bfc12d825c76f8f3777ece3716468ab67f16b92ec7198288f3307ff25aa352dbccfab5d1f1ad389aa8702cd6884159c4826d8adeeaa065d33a" },
                { "es-CL", "0b319a0a2204222d86cb2aab324b5ab7fa8119308c14dd1ec2b06116a04a6a0271f956a6e0d664ddf556d40c21e8c499ad65b3ca8deb34d31fff825df6743904" },
                { "es-ES", "787244c8ee56b357afb41305d12b492ff2f1236f2e27ad2a8321765b249c612a7821ac69e72b3f99cf0b10a8ea4334cd97735c771f012e27934a6735ab3a15bb" },
                { "es-MX", "b7b756724a6b6b5e49f7022a47d0a71f0e8dc8fda160cdfea44899289f7b720d63e0a6aefd55bfd31ffa1579c3e4d640ce81c866bc3c825c85daafecf3c21354" },
                { "et", "0164c744e74cc5584027118708b480d15922d378742ae00ed54a918019b727a487ca744a38c32707f1adf780240183dc212ca4a135126564e7afd946cc5fa748" },
                { "eu", "928e74a0b7d1648989e7c3588cb10a939a45eaaa8fe4e5f73d6dce19ed72e27191e8c2a4161d985c79f01378f6adc721fffdd815ea294b444d39bb0fffee5734" },
                { "fa", "e224d077e37e7706ed19f1918f14c28d59596e4236c6e77c92e54e78c2c67b81023f93bda191651d87a60b77f1ad552af2872f21a2110bbcbcf3e9eb2db3444f" },
                { "ff", "d432a420ea0eb7176ab5b6aa896c169efd9004785c1849796410547ad100f41c634fe778d20ca39e2e4f1acdff2b6ac0f31c3d83f844d4a6a2ec73e5dbf886d0" },
                { "fi", "0bc9e8a19428b9d28cba9c37e904f6cfbcfdec82c34fbefb02799528828efccfa281a767e691b0fda36bce73a26c07267c45dc5c204214fa03029f0c33d92804" },
                { "fr", "404c02f0aebdea780944aaebf90d7e5588f6e404a09c7ffc2d28cb49526d36beaee5cd6a151d072dd78f5fed8672eb77af470316a054467ad4583bed72324ece" },
                { "fur", "f24eaf0c851a0b4d7e2d6df1cd1645676075a520225c011a5b9c36de4bb0ba8eb585c9cfb08b8267b3ed09a4acc44d52ed9109cda786d91dc0e833085b629076" },
                { "fy-NL", "3443545d76d264bc419a70c96f6d6d3a8efd6b890cabc81d31688f93060a821d5d0df51e2c1c9178bf0388bd659e6fb2021cc77cad3678d1ea10e9c115f00acf" },
                { "ga-IE", "724e5cb1b2448d69e37bd9e1ac3748a474b365c9a5e2ab5cff63da30f3e23e72a6096b5a8ad768682b56fa5d6c44b25610d1b1c91943bdb09eead021966fc0fc" },
                { "gd", "94cb35c9899f87cff6829f61b0156bf171b242878cfb6fef269d2be57c829f89c7a2bac88dc07f6ba63ebfc3c60188dfe71e8b7828d7678c1e71b51c9aec168a" },
                { "gl", "a199fb55ed590b74a8121e8e770161a0b5c46c0b0ec4f495bb2aec39d6c6d52c6abd37a4bf4d0928b90a7bd956f9f5773708dd037a7d5c5fc4e6d7adf27d1556" },
                { "gn", "df84ba7b2e012d865fdccf1d63c09a3454bf18bc8dc7714280e5b6d8413fd21f181831b1680d020c5ff122a65abe6468bb8bfe84a9b95687490f0bbd46a02e8c" },
                { "gu-IN", "18ec5aa92ebee8d2960c41224954c19bbc4cfd6790bf7c88209383c7514401646af81d6e34d3bc6e78c8cfe898ab03a752d67717b370feb13f7893009921ed01" },
                { "he", "69877c34d3313c73fe076f281b09132bbb608148df1b88e4889d9870440443b4d6b20c9e5f3ff65cc47aaf51138f8806e2bff76030a6f9479fd3b6d5061d45bf" },
                { "hi-IN", "f0a99f1a77b6faefdaf11e7ea4d7192db84e27cacc935571b8a2e8d3ac90e759c3677cd9bbac24ced83b37519684823d0bc9353561ba4d8ca7710f1734f7c4da" },
                { "hr", "6bdcad0296be559bb3f1766e481d62a7d93471f49690dee60759a1f377702977946b37b3be54b4bf4b5eb991c628523eb0e1cafa22aa8783b88f9b593c783a86" },
                { "hsb", "f80b64d63da5956527367428e176834ba53a122f6668ca92f96dfc389e9fa8e6199e56ff15cd6034554ca07cd9eedd385978c7fced7c661f5fa955edc19b4013" },
                { "hu", "2f83ea55dc7a38e1b71bb1e536504563a4eddca8b51199ca75eaa316534181843d1aca59337f9ad9fe67c103b1373bdcc5c7719ede5f420762a8a1111f692c4f" },
                { "hy-AM", "0a77360bd38ad54844ae0c2109a5f6b6e52b6461dbdd9361eaea50aadb9ead02ffad38d9dba34a2776ec605fcbd7ca0a77d89791d4bf01923ad5abac8f7013cd" },
                { "ia", "be26a1737b441803963e399aa933a3be7ad6ffeaf30cdc3f9393c7f1d04c614f724d07bec696da8bc240e2e0d218388f9a305efda66198b2d53944bbedd0db24" },
                { "id", "81fa704e04cffedd5373d45b25c7a991e05a514f4487d0ea0b5a033e9c95c82e8164dd5952a21aa2ac2f8ab7a2a181c7c362d7fd187b2e3e076edb34b8aa02e8" },
                { "is", "bd03fa139ecc834c24ab6de06c9be40c1de847af7a451fdf7f5e464020cf8d802986285571b02dfed319b4f48f1ec1c08cd36c6cfbe4f6d9f3a975e987ceceff" },
                { "it", "3e9253293318dd97469e72f6fdc4f565c9e2cee7cb15d13bbabf3bf4f3af15665615c25cc1c9836f6d5fb7d895e5daeceb472ecde204d2bfad10f6c03af1f757" },
                { "ja", "d60f55d43745c0d38137e39b1733dc31cf415cd0a5dd3b3575ade706ad008b86b200dafe5db80d67945d030ce0ad6cf5334f97d61c0d2dccd70b4702f0d91492" },
                { "ka", "cadf2cdaa62338ddef9199f3a37b4109650dbf4949b73a95834cfa036105718fd3579f08cb56d456cee38a689ee9baae6cef670b03a4c4535d233770e5032d93" },
                { "kab", "a625b1b21a965826fa153e2d6287db2b119a5d59bce1ee2b455b279bf1759f3901ca3e9e395e2b820c130fa82a84ccf0ea84322fca4543cd88ff551198cf0e98" },
                { "kk", "b3e22da28e2e73c8dbbf7126c2c67a200b4e531019eac758d45f51691bde42d7b9931e5d6ee1dc5a7823e0398bb2b1f964e31a2dd3819a02e4eca8584cae765f" },
                { "km", "7b99e49124c48e28370ac1a9719612ae84483da6f8af879cf38c3feafc334edd8254c73320761ec25fc05389e6e8c98ff4e1d090da1e066b8cb547bec81de6d8" },
                { "kn", "bd1a1f994ebbc3f23aa52142205c542b83afa666dd708865f617346c7d9cd2489e2bde85a81f85d084aeeecd836472fccbf7cdbae3fa7eb9bff1e37d96f216b2" },
                { "ko", "848ffb1411eb4205efa2815cd9d45bf96631502aeca36d2841bd028c5e18b82d0ac5cac40030063a350267dabc5114430dcc13b3b95f8badef15fb28b44b1b79" },
                { "lij", "31a84eee02b31c7ade4a884701f4899973e63df899593446e63636a2b128812dae8d476447a5baa749f31c3598c4291159fdcbc29fed8020579bc10d17b63fd4" },
                { "lt", "35aa900a53d8f7d8bdd7f01aa44b8a126d8aefd07dddba64c7343cdb7f9317129f071252ebdd8f6749769da197e9ecd367301b0e89881551e03581271c342b5c" },
                { "lv", "7a2cd5a7b29110821c94130e14c17fcdcc642ecca3569ccf11bdb5759312d7bacef392e417b406ef1bad4f62ee83cd88542db57d5b6a2837f336b9e918aae51f" },
                { "mk", "0cab102f04e4dc93053e8dbda5dac7530079332d1bcc7aebb026fd684d8a97f76df4226ad2e264a400ac7e354fcc745686d57482a981ecd2ea291fd6ef905aae" },
                { "mr", "4e3aa34bf215b97a8c371a1eef3f6bca1edb3731a7838299d04464e20941c88df00912a491a93a213643ecf8353171aab6b72d43a59b91b1045abffcde4e794f" },
                { "ms", "107148733ec307bd569a9d2fd36508e8ccf7cc4ee1f8c509aa157273d2339a6a254e4bebed904b728cfd81fa039850b65f19791e54847ad6f26b200d52be97f4" },
                { "my", "195a37bf55569b954fb71d5389774cbbf1efbd0f19f512a4967f2026549edc6ef7312e2cefac0bb3c2d5b3a303024d7854c7c67cd235d82d174c913d9338ee09" },
                { "nb-NO", "fa696ae465891eb2d4ac53141efeeea77e10eed703f9676b97d5e677fb9d7bdf7292d369a688a7f32cff1e5c8ce50ca628b366c6bb2931d9289c0f0a4a2d4b3d" },
                { "ne-NP", "8d7ef74aa03550fe82b7d4b88750275372457f04ac2aafcd52307704328f850a969ce3ce2663beb00206dc9a601a93edb53fdd67c8630210c5f32c845b7debd0" },
                { "nl", "eaec8f0683eb186229056e651a9a5068c9e9d5494fccb9c824863e27c07c9803410fe6ee246827b3a4a99dd313b2618e99c5d2bd3ee4121d7d70eeff41b33962" },
                { "nn-NO", "b087518d2e8acb1a2a307d1086cbceed318c75a7ed406a36b9a631951cc3ded2bf979268e60abf1a308ad087d6081e963300a64c8e782ab1661ac3920f22bf3c" },
                { "oc", "93d1a4f3acec38830f0dca1298a04ed35fa92afe47a8f2ae89399e1210059e3373c202870cf611064e9ab7cb394300ad4d39910bdfc72d650dd292ac9683054f" },
                { "pa-IN", "b8152aa64dfad5e18f4e3b9461a222d27de88e580ffe6b94bba4e4f43982f3d1960721eaaf428bad7fb88a4bed55ac8c70d03bd9ccf5d4a28972ae7d9bebf3be" },
                { "pl", "94932d6aa379d5e24d9f74820f7fe57530121790b19e981e844656d42a20bf69ebecc8b4a3136c3955017674a5253c81d03c61db2b77610f073006ba1e0a8e16" },
                { "pt-BR", "68ec042269716bedc07ba2f5783354af04e298f79f5e26383bb1acc3dd9ab3fddcee3203804fc21de744f8b83852a196283bbde53c40ed0639d918198f84ddd5" },
                { "pt-PT", "deea7a1725087fd7550c36adfe1c1a43a0d87d342926cf98733a52ba01058f328cda5e32074a97c934fa4a7ec3208df90b9057d2eabc83e44f07244e3547d2ef" },
                { "rm", "f31d70fa95034696ec9d0eac8642ffffa68d56b87b2d2206b1dacd3344e86bbaa68ce219093c73fde31ef847e76c6ac5a15e99d17c96c8c77d1b2526e3afff77" },
                { "ro", "30f4c55754d1a77bc49efd6c3b34c847495bd0e6061a01efbcdd3c0691cb9d0cb3a3ba4114517eb42936603a6ebf2ee1e1e2df5dfd64109aebb8d1337781f756" },
                { "ru", "0b0aafdf6552b4b7e69eadbf004776bea2627b2628fe4c2e03849e401a99e8977b83edc94c3b2a09f6f6bd4cb1cefad777a60117aeee41fe3dd530d54a56747d" },
                { "sat", "db1e213ee54ebf9fe786e657a57fcf8050b216d13966ba798ba1c56254faa8576b49cd9c5bac94430c2b8329e60f2e805cd76b469b0495601f4fb6984dbb99ce" },
                { "sc", "c992505ed3b240df91c73bb1b1d391c17cbe0a3e91560ef7e1cf3ea55b2029da4fdac956210c66173081ee470102c3e3a1442d6cf344147de38875a142eb6466" },
                { "sco", "10607068e46191735cad8b86403e373b5ceeaa05d84677562727fc1e74e97cb2af68006f2b981183467cefe22af468b54191158d7681daf0a91b1d2d31fc15d5" },
                { "si", "4b2de2c6b1ee4e6ee420b4e06da3605807498d20a56cb7bd04890d99f9f2e6ed6c62fd29c4e27b4b1c87d6d34ba94ba811a395994a396c424d2d40225e29f389" },
                { "sk", "e208b7e4ba4e612fb95d0487dff20467627b53cc70dece05568a1ca0fb50ba47429710c376628571244911049f0383002510fe04e11b0fbba44cff5b73e50fc9" },
                { "skr", "afe6958094bb7c47cece0aa3c99717f81824dd59ef1d6f6f93d044d878a5ee605e9e15b4837aee7ecdecb8272f191b593aa256114ac19e4279630ce944b8721d" },
                { "sl", "85c4ab0ab6413359a9fe359c23f165059d56480c11e3372f6d6142e1840087d8fe5207f0a9c3f407656602be64dd4d2ed47a1bdf9eb141f9b808a6556e2c1863" },
                { "son", "9ca3e70e4916b696a0508fab62eb50dcd83bd3b9dabf2736804d0a6258bd2cd5d003ff8168b27a07374427e82b418e562cefed5b64c51abfc283eb72ee89adab" },
                { "sq", "d35f63449f556be7f1e959041c60c75a0fcb6c7b3a9eb4e39e8ec4f2d14e01b5431f4aa73c5959f9adf89496f9f1f69aa57cb491807b4e8cec11f6b99f663b5f" },
                { "sr", "52928855a041711d4be5f2e2955ab9715621a7f6863ba7b73396cb6f7a2d6fcbaf4480c89296d7d474eed1bc5c3fdac24707854a294e9c44759bf20462b6ea8a" },
                { "sv-SE", "34241dcba8c3e4afd8ad16f2e1f5897fce6cb9373b01e4aedf25248a9c7a190d72bd9762a955e2c55a5a3667b1a16b5d339811146bdc5e33579e8d0dd3e397d7" },
                { "szl", "e1192b5b9e8d3215051ef320a61cb77be08463d53e3cc6fea32365d5208261df8a5804b5c1e76a98e0ab9ae81e681cc6dae2ce5fea0f6516c8add42507aae820" },
                { "ta", "e8b1a7620131605ab3dd0f399e20a6d285622efdfa98d675b73348785c663ccd4697748896d6b6d03f614195ac4d632173099f9e0f1e5338cb20e85a0e6f92c2" },
                { "te", "14b02aca59d75fca06a649be0341e5d2a2ad9d3b55128759d78d9ada15111e93de636a841e1bd1cb0d7e6b7b64dfd3eacdb68724ed894c3e2eeee29de72e928f" },
                { "tg", "44af9c9cfd9b6da570af603b64e3d0033f2ed4853ffb8f95c4bf1698a0371912f4cbf4dd6a28b7c3350ae6f66f64698b3c851b97519f53c963ef6dfdcf4e68b8" },
                { "th", "c614e535ca74e0baee60ae9dcc2ab4f1cb3a91e93c75bc38739166f9195059cadbb575053bb48203ac18c2f7d792575293d78dca016ced6abd326c0989016d18" },
                { "tl", "7b01f010f00e1a80b463fd37024912ec79d4217dc2a3f82b9206d04f5b77740ac3e1f57ccb7c27266926378d6c4abde408d4c9bd96e89a0ab38be70edf723f23" },
                { "tr", "241bb8d27b616c2f471d696f5755b7d7234c7999bf14b85055cb7d309618e0daaf5a9e4cd7c35a09376243af26c469af2aa8fa8368869eeb09dea71e8cb20d5c" },
                { "trs", "f1516ea30ac3ab7f1b7a9bd2e801631943725896d89f3879f47bce077c4902d538d49f63c008e626f973c2de0de3fe6ce76b00e178852abccdabd8f7380367d4" },
                { "uk", "abf1392d7482694ec55bc41a689c9c546c3d07c0a3a478c6d143f48e53c26d2537a1f8bb94cdec4839c07bbcde60a59e6654b007a9436f91acbd9748a1bd722d" },
                { "ur", "fed63dc8a0c71dee54eaed8e7ba38b724a4769c93206e14802510cfa663edd6d7106b84a54799082da56cc39788e5f5b0d97770e5938c6256580a7a476d31633" },
                { "uz", "bea70edbd9c2bdc4f570493e8f1b88ce6176ba85c6195a77c3b3c9a14197fbb93d524b0ebe5b66620cb7cdabb48fd592acafcc8cfae1e83b4b1f3a4597ae6731" },
                { "vi", "7187ac2be6413d75df6ffd125d823a3fe37b2fc70be40dab55733655c8dcd68f8b5e23265ac39ea81ea6b114f0528e305d6d42a05eed2c690dc2b7c13454c9dd" },
                { "xh", "d039eb4bf0f68a47d7c15e6ef11d36ca047b8b3f13e15c32e76d9703bc9808b759531bb84f16e497e69cd4ed3a5452ea9b2fc45b994712daa0b1a6cb92cb0a3e" },
                { "zh-CN", "37612eedba1bda4a240278ecc4eb6fcd63b24865f642c19e1ffb07bbb4192535607fa316d7b63d21f36ae1a2dfe49d8020e7d661a5df038cf116a28bc4769f35" },
                { "zh-TW", "ae4386b754962e65d91cb73a01991aa8c5c3c73163ad67ad6fe711b7655625b8d0018c6dbd50fabf875d4b5590ef14a3eead79d8541fb2c7a9490214394d1fdb" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/148.0b13/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "66b291bca83034e3f2e784e7bb994883669ad0277fc2db31a12597f3a635fdb2f626700cd6c38fb39af7ef2b12dfb56b4a2d9347b13f83f9a87c4b336af2e2fb" },
                { "af", "1524e0f7bc4587786fca183b6762f9544cbc8c735d322b8c170599be4b4e7be5fec205048953856e5689b39f5ba77a84f5dc7728da9ee8a23b6eb5663fe790e2" },
                { "an", "5fe43da160ff1cbd3714dd442c676aed13c1e638a7073da7efef696894c27d9edffeaaa31dd60cc06f57e35bc10b6047e330a419ce8406033c66199274053137" },
                { "ar", "03cf570f1eaedca5a476797e58d40f20d87c9099f0eaf276f7564deff6cedfde1ed669089a3cb82f812a82015e3aeceedc4c413ecdb69a2b0298c2885e787ac6" },
                { "ast", "4f9cceb6cc9731972a5728dd86e76fa0726ccc317d203cf4db39192b69b2343aab50e54d7b47090c280b140bcc9e3c756b5b5f588d59a9fd49c1029d638a07d2" },
                { "az", "290eed8ff34ca6f19a43b1cdde428be07c36d672397ed5b226bb82762819686dc2f76e49d62104f7881850c47f6bf5044230e54d8f0f2e133c7376414cc41fea" },
                { "be", "ee243bccbee3e05e64f9246be64be41c47b9244a7e0ac397faf063b480a4a458a78aa8b75acc4519fbd07428e2e4e8075e79a6c9d7b1c42c1dd7f5fcc778fe9b" },
                { "bg", "7a7cf1676099706986f9dd0b78e12ebce12dee8cad4fc70a621a07e00027c0be92f695f0f360f2f4279e15af1b2f299a0244052d8f2226a6db1fe2af9576d282" },
                { "bn", "c7136792061e4201287e8e4c1f8da584633a5c38ef116e19f000f393ccb2de97e7ee18f2aae4a8e139c14f4fbb64688f28c79e903e7e87a3a1d3403c7e466ba8" },
                { "br", "778fe8f653dca85831714503544d7b8b2d4f683e2a63d39db68082beba9896c0d3b7ab43e14c7755d9a6983c8a510cfcfdf0fdfec1ef8ed8a1eacb78f9906052" },
                { "bs", "e7b066d045ec84970da7fe9e3a453840723816396c9cc98613155eeceaa1f761e4c0d073c79be9e3d268219474be5449cbbda542a0df85af0b8db5b88c409acc" },
                { "ca", "3c4c583a239b5788268befeb7fc17e4af8b7afcc17d0bfe8ee1d10d26c35f6ca7dfcf7fba88cdbe295567aefba9167813bfe9949ffdd47df3a36d56aac0a7898" },
                { "cak", "739ec356f500783c8140f05e8ddd63ff898f9db3878e826227d6c9206e228ab63bff65857862e83b1f8d1cf09bee85c20e4986a2562c63dd4c70ccafecb8f787" },
                { "cs", "8271070617ab341b19e8dc0832945cd6cbd606080d0ac761cc154f859d30e74681054784472a34f95521de595da0c764ad2213a4c4b432e2253d95bfb48d5bfd" },
                { "cy", "77d573b149fd7055a1694a61dcc7f01ef747a9d5aba36afee5c7dcd618341cac6efd122a29c468add6de9f1a12da59d7558e3e8b6b8dd51aa6b14e47f036ad6f" },
                { "da", "2d6a27f62f43d530953cf782930886016f28c588f45eee2edddab09a524b2a6651f640d4e0fcb02c0c2070190a7d0269989c46260f514416be0fbc1527ae2e52" },
                { "de", "c1a5a365aba0c587655717f334b2c9b2497248c917968f5a7282be49c61df5c4d3a718ff090b7932793a46202331678e8aa1022c89c427b1b844f75e777ad058" },
                { "dsb", "99673f643d2c66505391281575681eb8d8cb52568eb594d5bbd1a84d056366c5be15667a3b2f75795403c6f237bbae9096ab55fc9463f54ea2f0ca0687ff9369" },
                { "el", "75b29f2fea5a0701004291dbe19cae4a719c3bdc390c66371080ffc91024fc72f82e1e90506df9a80ced974d79b8a65f97c482c72e3407d86c0b5c2b78b56c3b" },
                { "en-CA", "9f45a8fbdff09dc5c765469847dd6d73f6c6a75dc09767464261fa9af46dd76b37a3ad2ca4d604643613127b72f419d327719a6f8cb40291814fa94973de5f90" },
                { "en-GB", "8d5b9d521270135d27bda2c1cdafa8581c0350860b8d9df021bf25fdab81d998b83e900bc48ca6a3a762cb25df24a0037b572614eb3040f63c5bbf832bc24398" },
                { "en-US", "f290bc657d5f43d7f4e71dd28b3e42fb5bad08bc00f4e2f5a3a3e01082885ad172bcd1bbf5c6a8c23394e733461c421ff2f52699e75eda5a5a66d7895ddbe29f" },
                { "eo", "d297c9802ff6c6bad8eb5295b7f7de490e9b71f167c9f8c30cfca2774a20694782a2a56501c49cf538f4232a66627f332ff8f102fcb0eb04be48f75692b332ff" },
                { "es-AR", "897f1a7ab75f371194e72606d29c6dc7f897c50fc8c81d1b1113ecbc331859752b09d18a8a64aecca393425ca039f0ae5ce2100c70aacad91265095e91bf91fe" },
                { "es-CL", "697d0e556f9bafc28ae2bc199634b89bbaac83b2376501f3f7f5cd0bcecd1ff499e7fa39bc0e8ff1fdb6f774f4aa0d1fda44fda2ea9dfd440053bd268442ee9a" },
                { "es-ES", "1df8f53553a10f8cc1980d31e69e9d8eb6b0945c1c36682b959b40760bcbd74b5f0768d7bdc2d20813b6e9aaca3374a8ca341e211a84e48117f9baab8e1b635f" },
                { "es-MX", "6eb2f7bdcc088b18d68770d3c6659b080b22de383f31411055bfd28de341459d8dc940394dba6582be1d2a91ea000b8f51d5b25626200c45af1aad901518e828" },
                { "et", "1fa3e258870f9038e238ce6725b5bfd65891812f3efb79bc14c579136a76f3327f3041b349dd4c4e80bd64334b7af24c3dd73dacdb5694ebe597adf4eaf711eb" },
                { "eu", "85609f957298954634c5faf48bf26dc1d2e53197b4f093443701c63da0491f85a89409996cc1962732e9525971682e30c5503665ff2043a88b32906c036bf7da" },
                { "fa", "57c079c68032704ec87df99b4909cb9661b2766921557a004df16c6704031c2f0a82ab133c49698812f6272b7f952870afbc82d13f70d8b75ce142fd0a34d94b" },
                { "ff", "beb9bc6e14005e795a7850826b1caf1d56a221a31e5b6502004fa11ac86b24ec837ce7f9f5a343b0dbc26f4076c0c954c68a7e2ce258ecb886fa585346f05ef9" },
                { "fi", "a8b78cf8b877d23c673f02cac3baba5d589ed23011524ca2ba971a7be0f8ec9e924e57526443bbc33f6ff351371abe3613c41c78f45af6eab4927fa41b86e352" },
                { "fr", "9d969c8871d8bd4e4a2001e33370e20c4bd78fb43c4afb98f2fbf83ea25fd5082b573c8fcc7bdf9434e0efae7286369ecadca74f8dc897efa254dc34c0ad2c84" },
                { "fur", "0b7c9bd0e959b7ef5425d7fa65a6962ecd3f7f4d600bfa1d8a1e7097caf805c832dc4b86fd6fa09735893373aeca8ae4694c48d3f33768b874e8c382d0763830" },
                { "fy-NL", "c197b870675eb255f565096d358801ee5abcc685da36dda2f2e0e1495f6d95fb2d615c6eb26b6caa64bed60c8f3b64af56be6d9cb9202393e0fbcc79cd24d5a8" },
                { "ga-IE", "ddf0efbc854376d47610a496d48d578e337ee18475e2aaabdaf67cd3eef42cca97015d40b7fd9494d31b756e021de64e7378b7fd80433fab486fd85433e6e8ba" },
                { "gd", "24b695c7595733d4a2e0539056b211876f040ebe3cb9ecdb6349db90b70e8b88eb9152f040beca2f1e5f7f0fd639115246288d00b09bb6df658b007eda5fb4f9" },
                { "gl", "6b7e0e830f223adc5e4bd60014a64c5516d27a65e75b52e9ed9d4636e8dd6c6e119e1e6c69304680695a76ab31b9261cc20181895262eab688532d782cfadd09" },
                { "gn", "89d6f2364b3451d389d36853c9a286d6f1617967cdf47a451c1fac586d2e0589698ff72f20a0bddfdb4ec322b5823b3b64ec13dcd71438b93c3f69d2185cd545" },
                { "gu-IN", "b7bd8f43f80f3f016fd99672d7285c7626f88f0d0a1195320d6aab14bfa61b72fd535376ef6590922c938143bc276b0b2dca42d5c6e8a1ca73c2bb866f69f641" },
                { "he", "17c265bcb1bcb6cc335f72e15adcc0746c2e36ea9c325ea580ec9b17ed4d4d93e745597c8facf8af1ae0909a8666448e28d760364ed4f94ec0f88fc561d6616e" },
                { "hi-IN", "89e39fd3189bf5409033cb588b101ff8b056ab34dbd007872bb18055a7022d5f92c9ba1a90c1efc8e149072138d1ba065f6eeef01c7f3c1810a9602ade1bd734" },
                { "hr", "763a3c1c37a9ea12d910b871732c12a11ff95c73b5c7e3bd595cd3858f82ed9a633695971e34e8372b755669845ca68a896cec9c4531c7ebc095c3f087afd05b" },
                { "hsb", "74c4110fd9f206cc6fcbb2ca461b48a05e59477e3e58ecfeb1678f2bd5562d494cea283d065a996db383aaf891d103fc4f8a7900d66ae387de3f399412a728ab" },
                { "hu", "d62e24f5fb5572998fb24ea3254540cb8b32d0888ef10484652a1b91427b80168b65836bc888f94eec7cea69876342b77c20cf245107b771b41e7297f80ede5b" },
                { "hy-AM", "798fbda4d6144f8805883f86609ea733622538e9ff0334f8df604e663d0dd9dacc256a03dcdc37c40b248ab15c4f008f97335eeb2a435c3c9b875471930eae1a" },
                { "ia", "6f05b77146f1c524b230cc585b5a063913acf4db4dcd7f7bece1ead35a471822ac67b847d165132c851a7afd7c3f3a7eda6e6e58d418f542d3dffe740142f0eb" },
                { "id", "9371cf2829aaaeb4d569db08a0fc6c0b6db40980729582c524e75d88e7a01624c9c69798142ea007b3cde80b365e3ef4e0de8b926f2bc34d9c0c8110bc973e94" },
                { "is", "dfdff9329d0defe005e3145e7ea45971ec667d99a1b102179d6c57184ef2144dab436c2507bc9308ada7a7d87bee4180f86d5da848e8ee64b793111a73645764" },
                { "it", "ff0b2eff150a4b66af22a4cdd8fdbe90d7e70caf1137d05a121216efd505c002da3c5d2053968cbeabdd7c7ff0e8879625246f53c9fb47a6becb4bacddf0da3a" },
                { "ja", "e324bab8cec1939f40c86dface4ef961bd8d54740cea11720144be13acb6533a4d6ff8ea76fd14ca945c0cc2a1a2c394654ad60c5e570eca26a512c639ae28a4" },
                { "ka", "69ae3b3fc8502474222d2b0e650775cbd12f82a2d13c0b7c7c2b6f53e12e13525c461523ff68c1a494e690d14a76cbafc5bc0ac7e5d92b5fb3ecc9708783b0ad" },
                { "kab", "0014a2799cf55176671e67877b8de9c6c0488034a96566c7911bcf18342ad84b2898b4ddc99ffa3caaaaf252f14804befc874a1449fb262f822bc64d1f8f1c98" },
                { "kk", "86fe4782088878c116fba4dd4e6c408da35e5b0c1a028cbee85e998d91ae79c33ae700880efc96e525982621f1a4e14c38d6abdbdf358778be2f644934e64626" },
                { "km", "be65725ef086a7c944b4f68c542b4b50177089467565c7715a3c93a35dfd07134ac954c981e4bd3ca3ff9f3571ea023b2d8e42a36a9ba09668e3d6ebaf208afa" },
                { "kn", "06ab105be2974e439948f4f0f107497a0bb7862d636dee6e1504b8285b4c7b25367427a119b1befabd0796ab8d8889ca30bf131872cc39dbf3df2639e47911dd" },
                { "ko", "fe91b75f3f31dddf089cc3e7a43e8ad881fe933d1c57861ba6c995e735edb148dd0a23d82033a5d163fea60be9f5daf2becd5e915fcb08037b817fd8f6bfac38" },
                { "lij", "12cec9e1cc0cfb0528e02b9bce210df0fdb8ac4c804389a59955c7ac0c7dbf2e59a9b3145c218adccafb911cb2760edbd4378971718f02370edbffd324393a02" },
                { "lt", "8c84ace4a4ba5b3d0caada1b2eda2f20901f302b6163f0d1bbe058fab69fd11ce4443ea0ba927f1709c8ead3e16a2ce0e661623e0c0f508611e76fd3a02f8917" },
                { "lv", "9cbf1710f229e5c6f3b052ea61b7c3f937d7001312a43fc82e99b4fc90ad605d8c0bfc076d31c34a423a22b874a0a2233d99c34704363c3441c46acf5055ce8a" },
                { "mk", "1eaa0c6e6047ed30c28419d7103257cbf569e94f74f87384182ea5f992a06e47bbff43ded06396a966df381e5b466cdc6749b872e2bc8fd4270c946e2f4b46e4" },
                { "mr", "74c98414e9e83ed1fd1d2d4c93ac056650e3ed9da277a6a5b06fa496942ad3ac434278c293d4a26dcfdb480968686a3a7008d5686dbaad8be75878c0988d0856" },
                { "ms", "8b178045f3079c137dd433eac6bedf7c6b86d0bd15b12961cdf579480a4205ee78012edbe2c2ebd5d8ecd6a880ec449f253090573e03c2e654058e1a0166c3e4" },
                { "my", "6610c1a4933c48bd8eab9b01d72253c601e066f4570ade11fe35e0e60e2be66a35acbd2effb1901e64bbdd7258889b5cadfa60e4627c9c6f02f13daa8e5cebc8" },
                { "nb-NO", "afb62508feaca8e42335b4b91ad5b6baed40cb2ba1164c1d3b0e3f66755d28f697cd368ece016e8aced348adb0196f44aa5d679d466388f9bf08ac88de251eb3" },
                { "ne-NP", "269a52e4dc098c3637756f44abca6f917393661819361e6f9c4308eb74f2e4d003d968c59d3922ea6323bb65b4621ddd060788beac4135a898c551a282f6fe83" },
                { "nl", "52ea125f3554d0c12e2a10fcd2227bd4b5fd92efa2be1cf9ea4840eaa5cc1dfebbbcdcc41442766f086902ec3c158afae447ebaf0f4f81b1c34e48b4662b7207" },
                { "nn-NO", "a3e95cffe21bdbf600620cd95955fe8c3e07b9ffb5d98c681b83f6a0fa45392d82d22e0cb3818a0a37bfaba8e2a64128cacd9746821305e1f62dfe5a0020d06b" },
                { "oc", "e5b46d115997f7dbe10a6af61edbd1f37c4b745b4575c695a1c36bf319bd504c7aa91b87d1b9b974a1638c8e39c7a77fc8e1be1b6a8ac04176d88181fadfb7b9" },
                { "pa-IN", "4594b2a515b5cd2c73734d118b7a033e76ad332172d302c55593ae392abd4a804486df5656e7dd4b161b26002ad844ffbb7672fa03f47934aceb1df55812c704" },
                { "pl", "f9dec818be4f47960df05570fd2442dbc1b6fc85ef3c45146f6c69689f6e81601b3c61566b1349a43a188f18f3a4b9c6973ded6199a0a5e83366a35a84ba7113" },
                { "pt-BR", "2f9fdc59924e124d8c0b2f5d2080eec5bf0703cadd9229cf6a59b22f55faccce1cd62fd9faa8bc47a5ba293c23deaf962869f3dabd671837e7f4d215a2ab5f81" },
                { "pt-PT", "5b563645491ebd8668977b5cc06f035092479ba578d1576860b53a36d5cc80699ea428f633c4fe0ddbab0c73a678f2919877cdf1c35f9eb9e36fcbe94a1f2b66" },
                { "rm", "1d2b989500d27dd032384cd60244b6fb5c74fe2b0b5162724b28fa95d85e454b5636b13324e335539fa100fef3926a217d02d947dcad6e1710c2f197dab3553b" },
                { "ro", "39bb480c2015e598f8eb326b72a4cb2821d19f74b31b29a2b224927174f790085f5d5d985c6a3670afbf3f2ea3125149dd64faff057468fb4ea4fabae5eabf8a" },
                { "ru", "c3c6d3d912de87090c518251703d690b1f503690cd37129c9ed3cece386dbac58b738e08a68be06ed21c677500628c5818860cbba1bc78beb677c4163bbc7e97" },
                { "sat", "1df086b60001fde1fa5531252abe0df61420c41cda893e52260a7c793e78a045825a8a7a541117a10eb05c8de9de15418abb74afb173723141132e65f9ac1606" },
                { "sc", "d89dc7195c76257507a12164bb6fd1745c94513a51c11adc1fabae8372d18d25854c54c94cdf7e8641f64967f30a62401c029743eb714bcbea00cdbce1d9dee7" },
                { "sco", "e6fa4232485ec171e459982e4aee07a7846c2fc0f2c76e928130710a52b9562a44f434fb00eaad2a59159c0e366e97b26c1102e366e42d50e42e34ce117b2ff7" },
                { "si", "8263724354f92732c8c9e484ea026e6ea7f068090638941c9896767e9db1d2696d2fda806c5bc74546c040aae81a9c6ae9c7e7cd1026f2ae7c54f79e9b75e0e9" },
                { "sk", "c35ce2367b54c3a3561a97d4fc103854b54a836b05527f5de43d2ff6ec2a0ff09eacec4d9c282c9c1ac1d5a10b5383118f815524c9937bf7352648c8b78d6c3f" },
                { "skr", "c393cbba5527cd2095493394d061d0ceefd9209442c3e294aeabaca129657aabd37b06ec126a3b5074eb9e1a38af9adc5a26dda1e0f45429923aaa35943352dc" },
                { "sl", "2b244805974ff3c3da6d81ad2a97119d9fac4030d37a2547121e35e9abb640781fe7f6baaa20dd24961e6a9ad4d6971ec96336aa2d871e32cd79cae3a787f479" },
                { "son", "1bbe7ebb995f37ca306647198ddcef773ca4e08ca014487ecfc9162e598e822907b30fbff9d2e2278d70142e9466147db637421793b1250f5c3d43d90761ab24" },
                { "sq", "25f027c44253ac9052d8955bcadefc3f232389c8d6e1f9430b25ada57139098922cd0f87271e0e9b15ba48a5314f9e0c9a3952966d7aeec0df95ed65dc143f54" },
                { "sr", "0346418f5952334cb6212ffdae2acb34a24ac322cdddb50194505a22a4e4a2be12fa12f5953bf47dad2575aab9aad4ed108f83cbf3f988bff2eabcc8b17fff6e" },
                { "sv-SE", "f8a690bdc7c53a4123c23cddec486e80df95599e4fe2f6c635a2fbd5dcde93615e36fb16cfe80c16a416cae560383b000a1f5bdc1df94d3b0fcdf3b3a79ecf74" },
                { "szl", "662a8d3dcdab6acd4323a3eda75ec71bdd74af57350d5d268c56509a3a664580c6e8a034facbcd17a7a88fbeb93da09e588bf9e8fd4a0d2114196d7526aeeb60" },
                { "ta", "a504b87e569613ae697738a00d41718b5d1bdfa744915540c13a633c71c0e4f7e2fe44aee23058e6f8d20af8ebe526946205ca36e4700560660ef44659101347" },
                { "te", "608655c5065c687280405f7a798328f46a2412f65f248ba3017893ce5568dd8d6eb234d2275753ede74018b744d20fc5f80a5abf01864b6ddf1ffa2be43741a5" },
                { "tg", "dd10ad6ca452ca8dfc1006cab1e6ff0764a09e3a6fd34501bd9249e65ed1772de715613e16379afd565059b08a1e978d4b1b05259bb2166efaefa3496478215e" },
                { "th", "3067110a3af80463446bc988374e685a6d42d9daf1b79b43e1e647b62c0dca4162b8cb5efbea5b39d24d85e81dd17eefc8ba5a8e38e77e9ccf4224362f62011d" },
                { "tl", "e50191bc2e9cab7aba83f55859fade8b0ed92a753ebc8f23860cee1aec4da474c10dda93cd1032f849c59816dcb3c99ce951c8dd81430d28e9fdda652ceb1b08" },
                { "tr", "49fcc4b5dfdb2468bcb243682b7febb89a45d099d58a7cbfc59202597792cec4016ec15979840426125e93ac138280040c82b344477917b7940e8c85a44a0589" },
                { "trs", "3a88032c5aca72d43e29e68325573737b80830f693c6ecf5085a84f4fb7efff049a1584ded0df9c521f2bf045a8045dfcdccfa4c0d36092f64df4fda00235e5a" },
                { "uk", "b5bb1f215b21803c8dd5b562499efa529cd411abd9704d4eb9711edc80dcc0c3252c78a6f4043d3a44f863ff80868928f7d24077b7a10b0d6e0a8e1ecd10f6ef" },
                { "ur", "d88c452ed0920fb4605de43e818e98dd9a66c04471d1c82f496d6a0fd5a1bdcb95623700a9c68bc7d07b1151da9c0847edb66abbf9a09d81286c1e85b27a0a17" },
                { "uz", "5f88495027ea28ec0ef7f689c8c3a29d0cdaec4dccc1a188d2e207df6eacae004b5230c36c29e1b795ccf12c8e13a016782c008d104eaa23962e4740ccccb774" },
                { "vi", "27b5412f1a929f9cc7e829b6b29f1e99f74a2307dcc1805d6a47e9940432860ab6ddb1d01b91cd245a7be9e5ad4336dc2c3969e8c8af507c4267c5da31aec24b" },
                { "xh", "d5d87cb6c74cda32dc4e629a32029794a029aa7e0859970efe1d9123f11553c6dc784b7fa239fb78bf8a812200501f7cf21f73b5459fac5b342cc2b267e195ab" },
                { "zh-CN", "04b6e933d09507bd667d077cff063ad63e0275e5558ade3cdde1c37d69b5dd6716200c111492861f088398c865d75197f02a0068e3d94d5e737431162571ce9e" },
                { "zh-TW", "6a946ceb60e0253d5da77a7398029571744b9840de087c3f624a828f28469ef91b23123d97db19db4a4cb0b55f52cb676af609cf6278fa1e930ea688c5b507e1" }
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
