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
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "83.0b4";

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
            // https://ftp.mozilla.org/pub/devedition/releases/83.0b4/SHA512SUMS
            var result = new Dictionary<string, string>();

            result.Add("ach", "8b85132216846f90c1aacc7808394adef93a309146419567fa9be85f7faeb1a9559fd18a162bb7a7d415b70744dbbeb63e8f0e068d28b486201e899cb7ea47cd");
            result.Add("af", "7ea62f3ef4c90bfa1afb29456ee5f5da7a12f80310b29b7426b5cae6437ec284f77e883613d1094112ce639c0988d8a60923f2ac85512b27b76cb5b8fd382999");
            result.Add("an", "b423fbd490f3f9fcbf93cac9e84adcf155a18c607280a96e987d43ccf5e9952b2e73abdbeda780d62031704f6fdeb9649c9551c72e3effadddd95fdfa2907b56");
            result.Add("ar", "ea8ee6abf47bfd0a16076c4b46ec72511e3b193258fb2160f7024c6aebe2c7791aedd35340ca4d7f41ba4497bc9b3b4c6c7d3af8951da0b7884940a089775fee");
            result.Add("ast", "8177ab2b37a221e1f96fde0d9a16884083242d2f6c1d8d2d605e648fc76671ec38ad8fd5cd6f782459df76739e8d0c4c7a8abccc073da4baf6646fc472828c89");
            result.Add("az", "ea2478e59bccea4dd1df3a754198fa0d8ef65cd747caaa473e516deecd947e1435a75ff7953d810831555a53b4c8662eb59be34ae2322b4f7f3ec79a8942eb57");
            result.Add("be", "45161a22b986dbdf1cfa349875073b3ba7ee1b9ed81dd055eb810007d97eed1a31c8513491d6977464cf42c7900fa140c349d925f84d73f64cfe107e1793f6e6");
            result.Add("bg", "b94409abc8d307846bf2061a226a5dc5532178af008e0ed2c075078b3b8da173ca73c53b9daf0510aa8d0d8246b619cc8f1ca77ec072b7819d4f156589b86f2a");
            result.Add("bn", "00739dfc3b63279e63dbce4de5f01878c99ab2a016f9ff68ab22632784603bda5ef02bdf3a03bff48d1327215e591e427f17dbcfdacf11006055f9b2e2ecd8e8");
            result.Add("br", "b8acba7b66d3ddc51ebca3e2cb959fc730a6591bf894ade570c8e08de224356e271312c5a0f1f26f29a0cb347282611125c84a1b52d23a7165f5444a9e87530c");
            result.Add("bs", "06ec673f0fc5237725e09ded9cc7afb879cb5fb36c945c611e33968c1dce0483f6ab9a19bdfada58ff1e23575cc9545b95df321e12ae9565f60f8679814ca0b0");
            result.Add("ca", "c240c5982836083a8aee56324ffc44d5d58d006adf57b0521e305a6787f2eb1250515d99df692155bc3106e4776dfe2f133168bd5e80d7eb7f785643a0116092");
            result.Add("cak", "c448de681c9a4515149677cc612172205445837e2a10a08107305f8b61df1433805a1cdd672e7e5b812d6e0547d2faa3db53910540949ae5fa277ea45120ea84");
            result.Add("cs", "43a6c43fbc30e9dc28743c94adb3785571b09109045a8c4fde91c48cfd89882acbb5932e1cc3c3ec0d988028f1458df5fc600df1362779d81f3548352658eca8");
            result.Add("cy", "74d63794c1c1ed09224391bb216b3748232d1e9548a77003d3576f127082bd95ce2af0078c36c12e961f198e994922a46dcb46c00cad2e49f07fcfbb763692ee");
            result.Add("da", "8b4b53b1532bb2b809673c1db684a1657ab12b19a97149c9a81358d5a9355734434bfa6fc6a20473526c0d8c837ea4a9048255962ba928dea43c466b51b886de");
            result.Add("de", "2194e97c55822999a5d8315cace55e8782e9dbd02199ff15864c98a06ba2409fbca60cab4a69610d69eb72d94b18bf576a4cfd1e0234d6e4d7ce81b194d88c8f");
            result.Add("dsb", "94b88a8238ac53b8300060ef8d43093d78f65626d984a3c5648fed324129375490fbd7b090448e4be46c9ccceaa811c3fd1aeae70f65523c724d3fa548c8b94a");
            result.Add("el", "838303b40ccc2d7b4dd4dc90fc9d8a908db4b989e3dcaaacfc00d07e958aced6b797c0cf89fef0efb914f65c9e3b43dd4acbdb0cb80306cf15b61e3835da2420");
            result.Add("en-CA", "748705ab4f3720f93bf9aecb4ebda9072dcff36dc73f60982937104cedf8a40ca4221e27ede11771529991da647342e93d57968c679427827c59be328c70c2cc");
            result.Add("en-GB", "375faad3d942373ee2cb75517522729041e5268d7158d7678f5522aa19cd5c1f5abb678896065c912abd242f8967924bd6460dd7add4e88ba543676e9f6b9f22");
            result.Add("en-US", "501cea3e7df9aa0948e368b820c4a580f94be1185d833bde4cc647ac336558360b3b5232818fb4ef4574b1040a092cd1ef39a6e6e9a7496d97f4b3b9fc27b306");
            result.Add("eo", "ecf0cb1df6d5a638c22c3fb9a38a9d6e2a03943e3574aa4e99afeb51f9afe0570fc5734a0bfc6b91228fe9fe7e1f74a29c7e3df2b2417c639b6216aaa67d810b");
            result.Add("es-AR", "440129eaf0cd4cccb7dc6d9604bac102e2312e6658738ef791d330577b4032db0aaf0d732404ab0232c454b9f53dfd01169a66f420d2cea4a311118493ed6841");
            result.Add("es-CL", "81feba9477fefa15592f6f563d45fcf99b56d0c490036a0cab74301021b1fbfd24ebf6cc1288a4d3d248ee756cca17d2ca97dc76beef67ad8682b4c39910334c");
            result.Add("es-ES", "ec94866aee7374e10362ce9b913838a653fd1d3086af5ea517bf0d9d05ade43a49067346e58b92115492b8416a88d9faa3474924d3699ee06c16ed9bfc330d15");
            result.Add("es-MX", "99fb6d849c767594a170a0593d811e872ecd5b0e15ed6567ad19baff4c178111e2775d359be095cebee6dc3a9d86270203db33d1f662fe64ab7f824cc4f302a1");
            result.Add("et", "9e02e4ba0cb9fe15d16023016d85dd0242905ad28aeb01f9155643a23b8f91f8e2ab59f1d7bcdc39b8153de2adbe0d9424149aced97dc35863fab5cc1b8b1ab0");
            result.Add("eu", "962f78fe88ac98e92c774c299cd2fb64aaa2a6fd329979f74841c8fb77d09d10ceb6b999424193495e0b255c5585127ab6bd6bd10a2e7b29c4edfa14b0a8fc2f");
            result.Add("fa", "12a931e1bf92dc0b465088671fd344131f413d0eba48dba54eca5150583fc3bf6e986da3b0a43240ce439ff1d2f99bf5d095f8cde2e51c766fcbe404fee5daf2");
            result.Add("ff", "1951afdd93d6f831cf554a640c066619861a22514048537a89d9efc75b6d7d4a114beb4ebeec98afc506c571761cdd7a1e9be3cfa459cb4278e1a95fed93eff3");
            result.Add("fi", "7e082e9391945d7a66da165be5f86f8c53e457ee35cfe8f603b0fee851905446b776ea699de7ea5dce4373fcb3b1e81b869ac46aa6e5d77e84c42d300757c0ba");
            result.Add("fr", "658489fa0c948aac1fae7323163fa1038ee60638504bc738eca6fb42c0511d01a705e1090051e828e0e20f70abc5026fab4d009cedb29b7e62d21a5d39d6eb50");
            result.Add("fy-NL", "25e72f80cb0fa5ee87690e5661d64f7ebb902386bc53b4385f68728e1959a16d6657acd0a2a8ddd8fe424e211f02ed05537fee601871df43a2fb5335422182e2");
            result.Add("ga-IE", "c3b57844f82a3f9a917db8bd1b37dce66fc9c7154d59f2974133cdd8bdec1f79d1d8869953f7137fb6081d1f73514710150f254e47345c8f387b6f78998cac4b");
            result.Add("gd", "fe36819b61ff9887941ab474fe419cbd8558c0da531c914abf36928379a3d8ba5b356916957524008ee8f1fba7d73e8021475f95b0f3b92983c0588c710d05e8");
            result.Add("gl", "f74e2858469531cf0fdd6dc33027b7c5b5c7601b89550840670788a696c253ca5b252999faaad276a13239e1336ef2d53e2b2de23412c7012277687226a6bfd9");
            result.Add("gn", "b262b3eb0f63aabbb20f88c0160c2e07292785adfd70118f56ccbe50809da2c5d80d9451c225767fbe71568ea3e3bfd0cc16837a1687970b574b9a80071b56e9");
            result.Add("gu-IN", "ee433062d1c10020b30d7c8455ab6aef453d9d9826fcd0157fa6e922b829811fcea8bbc1ddbe3621ab01fa2b5667aaf984862fbee6a273a6607bf325f7600db6");
            result.Add("he", "16b0a3f144af19296a4309a188c7579cbebf2e6af017f5e66bd5d4496c1120c53d0a5afc1233556cfdfd7ae71fd611468a321f0a85401c2bb9d3f4ddbc81ea12");
            result.Add("hi-IN", "8c9628c67b46adb18eb3323cfa6ff39d79e6bad01d196529f275ae12577e6a59e2e043fead84866c30290b52ae2b13971b4cdc3dfe272f52a4b21ef2efb2504b");
            result.Add("hr", "b5d96b9bdfabacb4bda41720a1d2801d53ac17279b6cf49c2fff480cd6a9c2901ecb2ce166f2faf5d16896a44740de0f6eda9f5ce3e7bfd56f8f745653049174");
            result.Add("hsb", "d19600b01c7a50b0734d69f167b3370d84142fa6371cd8654a488fd07abd4c6a9ef408733c2116cec4e4b5166783d6d2b31a90609d1c23d8cc79da96aa662842");
            result.Add("hu", "bea63618a716867600fb286ed7263cc839afd5bb5ccfb3aae516ceffa8e0c91b795d846c52b516488e63492777ad8e525fc06215e88fda5926e0cc89e335cc1c");
            result.Add("hy-AM", "5496d660b2ee409e62e0fde8acaad88a6d18d7bfb753ccd8b5e561e33fd4cca4b992e1bdec541fa0cdad8ea2326e6944a0e1ac1dbed989b38e4eb29e9fe99734");
            result.Add("ia", "dadc6cf424e4871d72bd44ac983f89a51f6d8b9ea4739c836baf8f39caeb4dc01c1417d1cfdd5ee3eb95c22d044fcf44569e89396ec5ab38b414fcb94e802f23");
            result.Add("id", "9c5e5e1cb6a25760ec7618a1ceb4fef5122c1b722f12cba0a98b833224705fb184ed992c194c1a1df7809dfbbe377dd8d63aafbb4a9732345e36005c67ad4097");
            result.Add("is", "e0af44b37feea123a76a30441a7f17f9fc27f2d672f810761e1ee649572f56d3471ee54e7296caad087e2bc848a01e0173a6dec531f84c545f2ad584fbbb0385");
            result.Add("it", "52113e747406989d533f197468c5d3df215008ba4c4c8259f52b4ad521b0d9a1365659f82348f039e9bed310593bbbac6247939349264307e77dbae6ec303401");
            result.Add("ja", "786b8024515c42300817dcdcf48c1e39352c5ac97b2f8569efced0e7e70abce41b9d789dc1a33f2e9848b9b0c4bcaddb07fba65644cf219eee5b77520b56ef77");
            result.Add("ka", "3ff34c865a88cb364e8e520bc9b4f0ff58fc29376c97679caabe8bd9d131fe4a62203b43c616a6d6844d353e7ac410c176f228f217ef19ed0005db8d639d9739");
            result.Add("kab", "88bf00a1bb96560df30449f592d6ff78adfc10481f7f9d4bb5253a8b56cec7c483c0b180844d808df048dcb3463e9e8b457da6dfb8814cee349ddf56b3fa0f06");
            result.Add("kk", "3298ac01d47e8379bfc3e481ebdd85cc67df9f2c4e21f44475b6a8caf9fd2ff532815df5beb075ad2eca1ac1c0474b2bc8f5252a17b6161100a2821b3b1200e8");
            result.Add("km", "5e7e39c260da1f2ca5a09d0a1e91341417928a6b8e6cfbd60c75a62bf2582af959de5d9c4d0c0a50fa0b50a0aab81893c5035a1f4fe4ff24a3330e12e828f378");
            result.Add("kn", "a2ef5ee0a21591c60c6b6f3081967bf63bcf48adb6ed21381b1808d11882723bdeacb506aa8013e46954686df04733f6d7aa06c493c25ffa93c0e99baca23736");
            result.Add("ko", "17c0a570ed13241f6e9106024d6951b5634755f2b894930f7e0df6b86a7601b8a3f19060c37017688741d8ee3fbb99f84b318cc4109c0ba6698856f17cfd5ef4");
            result.Add("lij", "ed4847ddad72ad9a4cabb0a2d89a234bc095a7278e08e4c1c58eb407209dacd486a9aefd149898492db2dcf2d772fd9c8a2d4c41615f5fe6001f24a6dfeda4f7");
            result.Add("lt", "a0599c598ad70f8d0e1c5bfb8801aaf3075467cc4cbf381dab8df4e77833a867692e624de88603e30f4210ff3f28dd4eeea293e76fff00c364a433702bec1af6");
            result.Add("lv", "4a73d557560698b0682a064b8573f03313eb515d75df3abad966fd4aada66a7d1f060645a290eae49bbc4b5da4c0c49e02da105409401e4ce8b8d1680cc8c6af");
            result.Add("mk", "2bd5ccaef2b240cc8624dde19f44b73bc3f1ae892528e25237f45faeba198f4b38964fde204893cf8a9324425aa14cfed7ab55dc9e0639aae4030f3ccaf65e30");
            result.Add("mr", "09ae1009df41153f9d3f181390ac85b9ec779b0191b6698767ee4cb74ff19dd95ce0686240ed6af64521ab430691ae7117100f212364e2029961121d2d12696c");
            result.Add("ms", "8ba2371c7b71d3defa558ca2863fd4a2c3e583f27ce566883855ff3e7b7f4b92bb82b313f2a6a8f4660c03b24a4ecd63d0518df888804ab8cf919a76abff3e03");
            result.Add("my", "648e6ea0eae865f00935f1885869625ed7e9e8569f3536460cd1827fd2b5d6704d9ecbeceb14f3dee7698e2f6c520534ce0eb22e5c268be9b9279281126139e7");
            result.Add("nb-NO", "b78ee092ada2dfe08d0952eddf17681d5f8878abcfa45f450473b944b4ef38c6097a4e5a9889d9a81b0843f1386c06f9489cccdb31fb95b69f5aa2dcea9c08a7");
            result.Add("ne-NP", "bb8f902a859f6da52cee33250e1de87a5789760244c44651f8196e14b8f835a2f47843503cbb5e9851850af2c87206e676c1a11e868781fd017a88620733c9b8");
            result.Add("nl", "53c7c5b84819c7cb14407622467d42423e9a22020bf70ff32161f202133bedcc7ab9705caf8d8b50cd269ce4644f864afd2ff59b473c3e13647d89a749e02f8a");
            result.Add("nn-NO", "5b175173a44884277120ec13d25ac01b215d0ed8700ae71d93d67c875844fa6d60541aed94657292b848d098ecb117f12ad9fe9e8b1409f78d9ef55e68085625");
            result.Add("oc", "e9001118199b8f44cdae7bfa02266e627b312c5c202c7b9f84e0e66fafded7a2ca06d16b342b9405e96ac38d3a22c0d3fd8786d5fa0067dcae4ad1522059999b");
            result.Add("pa-IN", "0e442b1ce3994d9380f47a79a77e73cc9bab380cd83a20dde465a2a677bf327e4a930a75992dc619a25470cb64ce89e8b89eed057550df8d5eb48ae5bcda1bdb");
            result.Add("pl", "7ee5139f8ba7e5900d29cec95238e5cc350b2317b0b7e09251408ff66c11ec82ae76f4c41a93bb9f8548b54a0e966c552e3ddba15272113505b5a2454c569ef7");
            result.Add("pt-BR", "496216daf08e1e220103d0732336962f104feda313c7906a23ed434ca637fc9a6cd27fa0ddd0cbf310a5c51f316eeda145c04356dfe6233af5f86cb98e3840d1");
            result.Add("pt-PT", "20cfcd4f7084a7b66b0cc63c25ffbe0385b6f9a1344f17a3f044bd7658e252315795bbc46f9a0cd5544c5a9cf7c26debbdd5d80c13d69f34b10dfdfc94fda9a9");
            result.Add("rm", "c9a46ed03e452f4e6426ab73c4576daa7ac93c823d86bfffe26ca89d1bb21fc2d863879dadee0b2922d7072294029bab0964e2cba9fbf67a4ab1f560734a8b2a");
            result.Add("ro", "424cb6dfa4de9d2770404900be266246623a8584f655bd07c52fb8a47c890a97e7f2b7f2e90ade6c834f92fdc68c25bc8d097392ececa0b756b399d60d8091ae");
            result.Add("ru", "03fa0014402702627bd5316b9c92e50d990e24105a161e4c831483129c38c75b51837ed328ba341921ce929ef5ae2e6e4dbbd116003c2ceef32d90fa38b7b754");
            result.Add("si", "27bd6aaeb65c42f85439f5bc150263c391e67470beced59d4dddf4f53ac06d821d186a73c30e7f8d574e24f355ee477b2b76aa9eea212c6e9937f1a22891922a");
            result.Add("sk", "7f03cbc1eb3b9786762440496cc3cfdb43b0ccbe24738c336b51ff4d6811bb87d2cc028958515f1cf7eb8b3eaa88b7cc7b02b09f66b7cb2bd8f46694d731af0f");
            result.Add("sl", "0d9085a6b74e8a12d41c01375793c5c00e6d6b23e504233ea631b294412e275e6eefd786915647c584ea7bc573e38d2b920490fa426cc83443fd58914447f2ed");
            result.Add("son", "13398c80dd440e0887042d43ef7f7b8833a14ae7def6816543a90c009b1f356981c353e305e2f21922732f338b242c25eec96a00a236b4e52e8e69d9460f465f");
            result.Add("sq", "647bc82f16e780c1606d86cace651c9b2f5c027c766e4ce738c95b1c5feef2cf52219cf7cd280ddccb40ceab8f27c22b230dbc1452a240ef5fdebb92df4d267c");
            result.Add("sr", "cae4cc488244a76714e94936b9d79363a3a38be9f82a7e29c141b53434aab6c2c7365965c36544c132f346ec7c940da2a2d317522e4f83aedc0458ded510b02a");
            result.Add("sv-SE", "3924e00669da29d54309633189fa718b425674c7c70e7ab1e53b3a976cc11a69ad79cd760bdf57169b3b8a725a54d2dddf2864aea16b71512283d1c94fc1629b");
            result.Add("ta", "222843a87c47bf00cb58d92855b19f69577aa1da7961f25f7d84f0b1e1d3f2b7afd2959792a892329b2f6b4e8a074e98ec241cf71a1a8ad42b8a11d59f0b3b33");
            result.Add("te", "e36c55f8ea1c07b714962dc7c5b7e2e1f050b862e2b7e3c3c1231afe4870de19b3d0db13b9351021719fe2fb1ce66422446b77bde81db29ac0c0203a779385ca");
            result.Add("th", "24854683637f20064e8a7a842a9da40dc19aedf917439ac1cfc36e1497a32fa18523a5e56e4b1f64eac30c70324efe2fd61c4ccd0bd77f9cfb5a695e1a2a4d36");
            result.Add("tl", "861ea02313f318718d8f5c92a4e95b240f70319f3641bafb243e5adaed5cb870343ca5555a18d0664465a78892f5924eda14d54ad661cb19520468c24678d2f1");
            result.Add("tr", "25801f482699bd060183854111f187553b847cff6e4c326bf43d14f65ded248c42de21c0650366660f32b920ba36e6c5feeec3e9500838214a8e153e7947a45d");
            result.Add("trs", "db566d5a2a2f3aa70328524afa762cc861d2020b33e657a1ddcfd1ca61c240bdbfc1b47b3f7f4330308bec953f4d8ab47722bc938bf833fd7fd996e6e6fe3f89");
            result.Add("uk", "984d665d82beedacf5c684ac01c5d7762f9e1e912384058363bcbd50df6d537b965e8c8550553d9d2bb1c609a5baf3f18452a594729f018e48105e6415b1a1d9");
            result.Add("ur", "502b716a7bda231d153747d82e07f78e352de98954e1f8000e5f32ad65ab9f396e11052d1c717c01a6cf2066011275406f96ff63f90fe9ecf4072b51b422747c");
            result.Add("uz", "116d5e08718e9a55912c3a33c7e7ee2410db9079132bff7fd20d754ba47805d930e222907a420febff73716121d456e719d3efcd32480ae187e1875f34bff1bf");
            result.Add("vi", "2ed1c148c1e8216fc5f6a04299132a3499132821205ff1ae442e88313a0da2f93450d603cd2aff29dd4be60dcf5cec6a848459ec9a4507eb057a0ac2b31975ed");
            result.Add("xh", "427bc2ecf771756b099ab767784ca64666a36b7538cc11ed1507500e6e755f9963df18d80cf824058b00488982f493d4f8f24d7cf5b8e68c18ac1a623cc44b8a");
            result.Add("zh-CN", "d8d0b1870227f5b45f8bc0dd8f7e6e688844f32cc102f23c380d6564fdd37c8a333e0190f5d12a19ba2caed46bec6c8981070746058576f469b9f1f573d43653");
            result.Add("zh-TW", "df31b57ebf7cc2bf8c2eef732a63bb3c0f1b95ac018cff3e99d187956eae2cfd4ad27f0e4850eb7a23e46fd50e0b7f18c6afed1670d2d00eb30abc286b11c8e6");

            return result;
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/83.0b4/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "44caa9bd02c6361af38fd5c982189693e614c44fdf3b85f27c533d3476cb5e4c05c96725b05c93dc6bace336c1eda4da935719437a794f4764e5391097461c4e");
            result.Add("af", "6a38ec24ca55fea422bc428a4e1c6c6cbc82f1f0f1c6c10b3e36dc8d945e455c79d89db783d15fdb1b033d3db16e2259f8ccce379a216bb5e36ff6c1c88dab2e");
            result.Add("an", "e61a1603adb8b8b0921a52e80137298c7fc5154044a8e10eb7a8a640e7739adad08d6eb08ad6a796a61fb932397c0b792008d52feb62a6fee59c83e037ffbf4a");
            result.Add("ar", "328560bbcf1875c2513a3041362172ddba60749522903a40258bda8364c86b9150e82e933751211c93f8d8db8f521df56b3fd545e27efeb8b69501be8c7d3a73");
            result.Add("ast", "f766027d782d7effed6830f6e7294350afa6f48ebfa33cfe9b6bb0abd6342dc755732f89bcf9176f8216c6a4c513da2f9dc1d8131abd6da92eddb90e3b0d0a2f");
            result.Add("az", "a01064ab753c7eb31570f73111968f68e9c292813e717b32228a577939acf638f4ae2a9b0e7d945092e2c37938d97e52b1808d8b004d70aac1521cc617079bb2");
            result.Add("be", "809929def71335d3678c42c3f676b10d6ec8f362aa28081b7afac8eda9b97170866d22ae9c6f303f90de6c53cda1767e63f05e3c36ad72f06624e093cc5c7961");
            result.Add("bg", "82f5d744b1166180465f6d230ba90e278cf092c01e1b3c3f2a0af23cff3b6833aee807eab7ef7162f60a71f19e579932be9fb04e4c13a1fa7c0ca0854909c9d2");
            result.Add("bn", "341c0a7aaeb7173be8222c3d514aa214f199e86a2f7d05a82c58dbb3a1741473149254479d217703b1b92032e0fcb22363b3296e0fa9c5ba3e286c2f77b7ea74");
            result.Add("br", "8d2001eb64bf4b001412d4b228c7225ff6bc089a58eb09e6b89cee059e08b0c2a3f024e86f870a1ffa3bbf8ebd2825ca17c7260a61dc5be1eb0072688115ed77");
            result.Add("bs", "93c60c5857d79a2d236edac77229babe7715b1391d974c116c5842dd31f0d038b6afe2ea75e0b2abca71090ba9e8debaf819495aa8fa59df7c614e668b2876c6");
            result.Add("ca", "bd98c155dde7ee679c8c4795bbbb54be72be16ca3015602ee637c90d733c713d889352d45419e913bf1fc4ecb6d22b6e4a1c3fb441d56dd24c78849db1064988");
            result.Add("cak", "5e16e94274b0bc36d8ed73c689ef2f1b750975ab97508011c196bffc6063c7484d498f48d9d4fb9d8b35d55042ea6653def3e18cce00bcc1a6a46c16de657007");
            result.Add("cs", "6ab1e966864b1bd88c6cc8d913aa5aabcbd6edde71ded846a52806f37f2fd271d9b8312eafba62b10735741babaa5fa42ac3b5b69b9fb5eb31082b1cc63d56a2");
            result.Add("cy", "abdc9b1b798efe8ddbf1d2911f9a02b9a20377c538169119664cb5831b80de83623acb778b084f7b3436d673119b05030ae428f09451b244e9b672ad1b4bdf6b");
            result.Add("da", "14bfd1467e8f2a42cd840eaf2fb49abc14bd39dded0b49fde0102403551947ed9574bd4c57b02086b0e95282f7345ff0d7c1f74c79b175d880ff1f1043774e94");
            result.Add("de", "c7631a4322bd11d0259435b0e626ef146a1e037620dc5cbba418a5cc80c51136f2eaadc627ce375170f7fb0dbec532787e7e79f086d877324c7dd131f285b050");
            result.Add("dsb", "31de19a82d73c6d6564b4a169c5ee940c5aa98db31e1aa75af3c77a6fba65af96990b8aa52eae21143e31ff8d48924ccad6628468a785054c112920ff8a68231");
            result.Add("el", "ce843eec41a46d516c972456100e970ce322517209a270a6784ca41f81e5b4a750506448b663f66f8d0bdb2e7cab0a2ed4b85dce68f1f7bf46b5a5d69fa84069");
            result.Add("en-CA", "56a74a16a4ae994f4e6d47c57338e8399c1bd3710dfe9e00dae3807dd8b8d4f19308d12e5014f4c07e1b38b276936f4953321f8b0531a3407a35ce6743824fd8");
            result.Add("en-GB", "a496689acbe3e990067966e0cd58fb53fc80e7deffcd6993008d9985925417fc13c07f01eeae2ca0353f613a8d3cc865271460a3e6e3c7db45758a19668d8c73");
            result.Add("en-US", "bc7902f53b3d8516d261e11969c4d23f4dd02571ec5dc8daf3610cd00af9f80558f454574d2e59536ede593295eb558644db53e43a436cbe14b69d7d3e5ba094");
            result.Add("eo", "2176c52862bef51ef53efc596cb128da02f893628c7eeed051788b82e3f7573544972e1869b57f77fa497ce19f5b8f5644dee7efd01a4f663344298ab1712241");
            result.Add("es-AR", "a8c0077e0bd0bba531a6e27da911159ad40cdec2c5d68272d38e574d34d90608a82e348c075e8498702b6fb3d072df400bffc0af4f877590ec12bf2fc6f26caf");
            result.Add("es-CL", "73d4332229db0416b1214faca4481bc283d9ad13861615cdbb612ad36e86d51c9fa410fdc8f5b0e4f83a2f27b5900df4f39ebef9ad2ae2ae58b7711cb21f0ace");
            result.Add("es-ES", "e2734d0436ddd4514b6ee154cbd30ef69e2478ccdff20c1e2d278361ab659449bfa250797fe32d19e5f9f7861c518b8d730301b741df269c48f5a0f01d4aba25");
            result.Add("es-MX", "45869e938f92258d8fd588886ff27df66c8911c1caa2cb35165632a84c31ee370f1436929e7cbdb080a54ce6aae876d03aae074a3d70fe657328c9bc9baa00d7");
            result.Add("et", "574d2e062a6b93b2679f1a79a1127a74908de707abf3212509605325f0b6c89ce4633fdfa56136099d00eeb864e796682c74c87c3cbf594ff69b1b66b3fae43d");
            result.Add("eu", "d975d5489e3a8b94d25b091fe866335e913f9d7a96dee66b8a4a4b25738bc51ae813c676ece3c49750dff7b15a126731fb3bde5c4048a5c2c988406a0a25c99f");
            result.Add("fa", "1a39a15f540e5d16246ac0e03d0b3fa9d9c0561216351de7479ecc0e14b5ee7d65b3c975b3d6c9ef2ce8b5852332b7da38b969a62ff11fb3d1b5e69fb7d0b8c5");
            result.Add("ff", "49cfa8d21cb8bc9f8bedadc08221d8de3b4a07aaebe97226f7afe660d1b747664c976d5461265275f9cb0773341ffbbf2b128616aa8df59dd5e25a446cfe2b87");
            result.Add("fi", "ca53e921d5861d9c666e8d4f1a6bb88fde9bc7937743d9ee58d4a8efabd1cc54eadc08618b4959c3ec2c89e51c641f18f48c2c332882f35970d53924cbf6f6f5");
            result.Add("fr", "7030a6f5a89813c4f71dbb46b0e1639175c8845ebc670581122127a7836c6c2e4afdab3820e60f9249d361d9efc6bf0bf0232059e21340ee2c697cda761812dd");
            result.Add("fy-NL", "9bcdc7bca37653e5a30dca7e90d687865ea67864cbd20caa79c720c0a980af8883dab9ad9893d0b4cb288e86f749835383eb049157efe562caa207f94979f8d4");
            result.Add("ga-IE", "0a4ae067072f932cdfdf0df195ab7b74bb49a05ad3c04aae1d52be35b7e87fdb53b143da2323a2218cf7434e4c711ce4f673a106f7d0aa4064cf737931304d38");
            result.Add("gd", "a64901c5e65e138f93f34b82f33e05592f2123356b9ee0d0bb165c4bd65e801b4dcf483a9a0cd35a516facc8127125d3c42ac13c23df9673d4d744b2071e95bc");
            result.Add("gl", "91a02b73cdc6f2d6bf2967ab53398268a01ce94f7190cf6ec2665a5b9caccd8bfebf5908bf6037c00b9172154a1543abbb526a37e71778208acc013584d464a1");
            result.Add("gn", "1eecdd9c95af291eb9095694f4cddeefe727601f131c49c6f89b44c1f98b98f7bc2f4225e508ff5128b796a29aaf27e322d43c7e73c9ec5d341cc5b94ea6ef29");
            result.Add("gu-IN", "b4cbeaa31b263df44b30494735728546d38842053fa8dfe455379e99a7e927b97db5e88317cf91c59d712207054017ef442ffeb1d6355fa8699569ba755cc679");
            result.Add("he", "7271ddcf8788a6c1397dce6c59d574d8ae23161aa6b98bfcf302f1cc18f1f49854732cda8b30fc56bfe5fd753135df8ada49ca589155993caca8ea4242405a07");
            result.Add("hi-IN", "1af1b776d0868ec5dd4294fa004d89e6588c83857a97ffb6144d541ad9b6a2c210864ae30cbc8a6653cece8e804c06505d327b9aa9f94de8e39864a0e27e64c2");
            result.Add("hr", "d1f242e7eaba5ed8803b9c1ac013b1558f6e17966d8477e7509d9d3e65fa4c5a8995741544fc5d313e40e558fd6dbecfd25947ab1b650767ca67a3cbfe81bc97");
            result.Add("hsb", "5b89c78cff838ba64229cee9c7bccfdecf1436aa802cd5ea80d628dfd201d6a4b854011ccacacc60a99904f54742f3a5d82c70aae7efc8b8067fcb7798814969");
            result.Add("hu", "4fb045acd360394341e689bce1422ef4d58af0f172a0c31419338ba0a363989557188a277f93a6947fb94f9e1194b32224eb7969b9c124ec33d6ebbaff8d59c9");
            result.Add("hy-AM", "3d6fe22eb04cfae60d418a0dce3cb9be29dc71fa26ed0ab4d4635ca2f24fc640cb38e8a4f5184b994af24acce7abfe00e8e29f680973a5c5fc822959f00c3783");
            result.Add("ia", "57392381682169119c642be8980864112d65de4228fe94590fd222e0e4b6547adeb5aa587a5eaf91b01aaf0647ed8d4039111378cb196379d6ecb8752cdd7b04");
            result.Add("id", "b6576cd183c585bba45730ea0479f79db59836a1c86f6119e669a120cbe28416d0462562fc7a6b245958f4c0ff715a510bd975c35b7ef83c351ed6b95215e406");
            result.Add("is", "1195f412c4f9d63fc0e49c47cd1f8fa83e0ab52456ef9f5a6e6f4b304e335845f05c17e70c42fdfd0014baeaf6e5dea3cfaf1b64a3c36526e8192c94fd19b32e");
            result.Add("it", "044ec27d7031f9f997341cc7b1ec50eebc4102b98d65c1814cbfc61db78fc83248782cc6bbce5eed84da46c9a306c629e9cb1a8b39c8b62dd9da276c23f72edd");
            result.Add("ja", "6dfdd42a371a50cf738ed53f85c61408132da8b1a62e4eb382c9c86c977ed3993992640a6cd026a6016d01c5049824a51309590ae10eb67ba900ef851fb9b9f1");
            result.Add("ka", "3d875f523e94d1ac3e31918e564cfa8dbc1ec02d95e00caa4a0c7b41c16947ba5e1d28e97f5128db609374baa5f5a10bfe0d523af323f500cb823fd892168fd2");
            result.Add("kab", "99109861de5b5b0d875755515bcead8d99ac7047ef3833d39ed3eaf2a69ab6233673a54abb1529fb4f57317f6e8eb8cc8f9546182bcc579e4b7e0e4b053f2b8d");
            result.Add("kk", "e6e2ab044f72778d39868e86d863a234a81109f3cd9239dca1787e7e0cf9693785e324407408616064ced11d9c5e9f30a60840cd11ac4fc93d2e364f11b72679");
            result.Add("km", "0aac8a22ec05988d8a88f2737c5539ad20d07fb2e5aec17e87e36ee1c2c5481de3e0d2ade01be36d9820b0b190dc4d8fcc01c1b8f9103667796bd10896819b80");
            result.Add("kn", "ecee085be33d2851aa9d09e63931604609352ef42fac8c601ce82afc5b16fc513a2ed4f7d9abbf633520807169dd56cd948b5920ff8075ad40fe5c84e4955b0b");
            result.Add("ko", "1986a3af657f62f358b7a926183f8f5aeb0bbe5bd301c8f89bb2b60913f579cd4a361628558f52cf8bd2d0eba7d7da496d24392ab0f0d1543918639b2a9ba003");
            result.Add("lij", "d369087f934a10c53383a6216af1140feed0429613f7a290435be778b196ba154ecc9f71f09af99d8229253e4ded1597cba43a82b83480e9be9eeba59fca2851");
            result.Add("lt", "8d542bbc695cee3063558ab2bd2d3bf92e3de140e386953391d070ca2992287322a25fa969a828c206e122d550fa3f0c8566e50e15167d67dcc1fecc5e50d3f0");
            result.Add("lv", "7cceb217a9156be7b85a3d6dbe26acb64e71fb785d434db7ebaa67561cbcf79aad0c4e63311f17f984a91ecc9ae5447884b5ed725ba6b9d3fed15b8ce56c2dbf");
            result.Add("mk", "c32a9d2d04366c3675c7eb08b15d6e91028b937cac6ca9feebc5878d0660289d285118641fa7b7dfb86f1d2f686571b8b5d236870ad08da9251c57f08f927aba");
            result.Add("mr", "1611f32f9539e71aff7ea0ad0ec840ad45fd9cfafbeaff15b1c07599b7bce81e595dde0302a338ce67c4b854eaaef68f56eeeaf026d144d9c4c1478cf7da3f82");
            result.Add("ms", "c627aa5dc7d1ce365d060600d1de9091e601afd55c6a4054e6953743770a016e8071e6bfd8f35462395fa223a9ba7f5475181191d22333b191c892d081c7598b");
            result.Add("my", "a9c85e99fd1b3576979a460c5f106cd23490cc105986621032fdb9a7a1e670926e70496811d1f1922d5f3dffb388fb9fd40388a0ded1d12fd095fa347732c9e0");
            result.Add("nb-NO", "79800f70f9a15a0839cc37aab51419bbf65a1aefbfd0b1c7e3cf31cbfe8532b98689a51f2f79afc6f04e38570f02b7ab3783fdefb4cf47991e873883b613255d");
            result.Add("ne-NP", "931d4a01d9a9e2756d7ffd95e58d3b8ae00be5212e039acba79644b9e69b233a0647ae0ca4fadc17cac83cfe170d14706cb266b9a7675e56a01125f9119164bb");
            result.Add("nl", "43e574483da9e50e105d15787ee75599643870138acfd17da191a76fbaaf69b35dff08afc410b50d794e37b679e524ea1bc4adbfeb12f61dea8033353a62acc1");
            result.Add("nn-NO", "0f5e81ed5e920d01d85a57cc92b1da881de6ed3cbdaa20bd46775729720878fcbbb12d726720f7ebc91d8e09af3ab1c206b1af8c0448606266d92dbeaf117f97");
            result.Add("oc", "a5b90e39ea1cb1e0f9f213cd71d09b5a03d6f213d42d5ad81be1d14f9316caacee07ea8a22b90d41ef1eea95f009ab894fb6f9ff681511026614c7f4ce62fd05");
            result.Add("pa-IN", "f15c35ce59a87dae97e7dcd438a31662672e71f199a0bf6016c5472eed5206cf90c3df06f59d0e5c1d3a8e2a15985575d0050672048cd736555289593234dbcc");
            result.Add("pl", "91fbf110ced2283aec96ee52c039612ce039d6549bf6031c8b886e7b604e3a6f29d6088b2572a97faf2e0b4e55d2d7e521bb23270df924a1511f48a2f7a76e2f");
            result.Add("pt-BR", "9f2886c885cb3c2f83a936fe9d5c27a5905bfbcd61293a1653d306607e8408870b33b8a8c99d18d7fc563a5533d3eaaaea68db3feae96a3908d1d6b1deac29d3");
            result.Add("pt-PT", "ab02bca49a88b31575a07e82b734619649243fd7ed01d3a6b2bd38e776808c11e4c58cdd5d6cd957380457869aa52d62051640b7e0ed3c3cbd4d09a07938f8a0");
            result.Add("rm", "ba94c3c1a48e07d150797eb8b4f366bdfda6857a92f01c304b634d314c044a9ab8c773071865b10a7ab4924c548fd2739e68d1cb756607b354325333991d125e");
            result.Add("ro", "8c8178debb9c634c529a037df127fc6529b50ca5bb1fb57b018a659ae8779d8adf796d75c2adcc9f6ba82622c2742b660ce9c7f296c6573d7da6a0e8b76ce41d");
            result.Add("ru", "e1a3f7d685c072682fda8ad9d4dd58c90cae27c0e37295a08b51470c58d0f0a57d5aaa717028b7f04b295d864c30b44806a905cf365c566afb0484faceea75eb");
            result.Add("si", "194ba87e20fecfad36c1a89ce61b41d785bcf55f2263d23d439a27537e2eecb4fdd14b426e783e7fa348dd903dd0da5b79409f0e080f6c4c00539814d679ebec");
            result.Add("sk", "23b79ae25edaf2a64721de148398fee6a919395a2a8f43021bb73c344bf90b182833550ade49c6551988500d3b53c365f5416e032716f7c9dc0d7892684a0b1e");
            result.Add("sl", "9cabc97264205bfbd53ba5fb05994d2051e5c0ab124c07111f706a660bcb033982d177179eefbf7e5769490167aa27d37e916da8009070e2104388d272a0f226");
            result.Add("son", "fe48f27156648c1801bd42488352679aef42d6a54049f41a9fc4b09dc93445207412c94557b0444cdc06c4aacf7844eab561a2b01a8e55fa9c433f2742693155");
            result.Add("sq", "e17c0ad09bf5316a0e8383526ac51d5b703acfebddf4e5227988f1937660d674ed41bbc32dc64f5f97a953951dbee794c84c4a8714bd4604dea16917d3cc0d11");
            result.Add("sr", "f3a6c9215feba4abe77246f3ec6d23ba73fb30c02bd5ae65fbff08fbe17e74726b874915f8edad0c68953f73bfcbeaa03c655d2185b0292e9cd1f9f4318a90db");
            result.Add("sv-SE", "675aff894a61f4c8f7713473b4802e2297bbac2550876167638461237aa258994309ee6cd0de03459464c20fd64147856289e7569e906fa748ffe6444762658f");
            result.Add("ta", "07bbaef61621b99a679a2482c78f6c755d7e0b2f0dc65be974839f909c79bad540cf9bfcdb92997c4021c9e5ad767d16732d9fe7a387a421440779642e4ee65f");
            result.Add("te", "77924435fb8f79a6c3f50b21fa19336315502823a47fc58014184782fb1b0ec133d63022ef248145c9c20ab70c9436f04c46a934757e594d3b381072d57020be");
            result.Add("th", "ad71d5abbff2bd4fd3bfff517f6476b19907b11ea831a7bc9eaae84e4a3d6b8108708ea095f7edd70b06d9e33ac20e8eba9f33049b0867b07980df4c002227da");
            result.Add("tl", "276c6c306a3490e0264dd47c70f53d0ab91b22da7ebb18aad0358fef174a234f934eb84b98f3e7cec0e4f1042677f5a38016a9730f4aabdbf6c337fe70a28c08");
            result.Add("tr", "e99bc711735ff5bff0f2ea3fe4718b9811207a72fd2cd3468f0bd99a614f5ae0111605090ab87431971b53607a440d7213bff3c1c252eba1d1cc6f2a3d80f1b8");
            result.Add("trs", "3824115b6ca7af8fe3a53f49aa3330a5adce767bab0e326571beff37bf70dafd04afb6678115aad4b77027ada3987dadfe359842210fdbb3897056897aa02cd1");
            result.Add("uk", "166de3bad78ac0eb116f434ed05b46c727f7f847ddd817f6fdfe9a58c431d78875075901a65e2be2d7951f2255c2d655d1d00a18dcdb5d18bcee1747c4d86536");
            result.Add("ur", "04fad71e8f511d9301d4940c05c652522370c6ea68b1bd9f8faa4a9bbf0df1eb64859a0350ee8621e276c87f2754b851d74675c3fc71ae8812a3774c43019f9d");
            result.Add("uz", "a2e2b423bb51c6b101d05b89442abd192246acad66a50087f5beae4edf8049f48a15929a5fdc32b8147a1840d0e507872a67501e750cdf6572f8c70da3649f3c");
            result.Add("vi", "22e6775f24c9af1dd32640038703e90a91b5b923c0a01e12c4462057d3d9921ad33e13b4e035ee0ed50e1458397846deb065a0470ecf23e9c3246c9a174053fe");
            result.Add("xh", "24f9934f8835fa26a610627e2c0c7c65a4258a148380df9d2774c7a21464861c743fc8836d1495ab42b693421439d06ef205df4b6cc730d40f5d0541fc192da1");
            result.Add("zh-CN", "73872953697c7943562b51415073960add558d1e5986fa2a25cee1acfd0acad0078714437ab80869c6beed4677d224ac45442ac50ec9454949d54c793f6467d5");
            result.Add("zh-TW", "f861c55af37cb4c42f0aefc8b8b4a0c2787ac3e44b28a5a660b296405b77fcfd461502f83aea9078207bd6ee6d49f795a94965dcb3dd67e310802d6f4704f309");

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
