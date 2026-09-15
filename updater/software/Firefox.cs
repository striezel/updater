/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/firefox/releases/156.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f0efe7813ae30e1a1cf3be188587770bf6935de936c2f5f6eacdbb98ee8abaf23ea055bc1d9109f19f55639129b261e11b8f7fe8bc9393d8f992b1c0291e2d7c" },
                { "af", "c85ed470ad4c505ffb6bb206c9eaeda4aa8da8ff109e34916f3f118913f89c7c45991b60d9f04f7a3d32fd473b0c27542de1ea1dee70df232ff0a3a0f41bf46d" },
                { "an", "c3f744091781e8e8c8670d1a98870f6c110e61a5de1e3d3892cc1349d17afa61d2eadb42d4e0b37f153ab471b19b5212ddde17210258db442f4c1c902d4a38ff" },
                { "ar", "8919f68c917b3d4dfece994300f441d23e962ce66e3637eacc32e220afe1bec78d3b63c189d55a617c5ca288435bd3471f0f9996183e75ffb1045f84bbb6f193" },
                { "ast", "217660b83a859c0ae7a80b198badf054f4cb7b5d9b05e0acd809566f21275b616d7d9d7a7542fc108a89ab1f135565f228710fbcac8dd88bf70bcae9750671d2" },
                { "az", "aaf0c86c20f8608727fd609c083d85a30c8352b8bd9f6fccb9a2d295185841197b4915db83f303595d53a82e93549d4fb8dfb928c36df1fafea54caa33828a53" },
                { "be", "ab8f8be7d1bb5fc8453751ea225f7bc18c96f3386366b8dfc9c18d56e1620b864ff1f174a5c0bae8b07c83dd64ae4a408825422383f36ed64a3fb92a0e6ac42d" },
                { "bg", "1d7458ebd3ed5a931694e1c88afc1b4e7b8eab70d0ca67aca8a9d3e7fd4cdd72dfda745f7df815c857f14ba44c9990d8e67949b24f08360468146c031b38d2f9" },
                { "bn", "e2ba24bf8738a4e6c5d73646d12b0e14fb9bb2dd44731ba01a49e247d91af5f68c66dd9e20b98cff9d197de578454aaec690cdf8ba231093f01bd5def34efc00" },
                { "br", "7b7c095c86cb36c5dba8826e133662c4b87f12b9ec398e0dad5c7be9f68f601f0d82da620ed84d57b81910d643cf3327fecd180294484c123b1dcba495a30053" },
                { "bs", "85426cc123d408f8673da3093690b47814f7fed1a2f55de5c7dac489215cf18866f3012071a747b3ed4796dc2078171cf9a0870f980b6621ee2150112f060ffa" },
                { "ca", "bea7984ab788b57fde5e46d1b364f5427d6f01ae2438a4d211c9f502eaa800fab11efc9858a6789bc827cde5feb67ee9172e47d9facfe265d5714515766c7794" },
                { "cak", "a3c34e337e531c8827dce8573bb6b8e2c521eac9b810a389d3c130b8e4301e94f9341d942a06ff0656e83483cd9de66612cc313eaa45b205252ca641261f55e6" },
                { "cs", "08f58df64aaddac06f48a8679fee591802d8b5bc39aa0ecf3bd0a816bd17dd2f7aecf81f40c337e430e2d8f26ee4e9ab4aeec6f857b33891fa593caded2b009a" },
                { "cy", "10d97de9b22c6711807e56674008063b23cb42e8cf3d48bb3864ecc3c96648587156fc13f3c84009165997113bbd558411320c7ec6983e177971c143bcdcf959" },
                { "da", "cca92912423402fc22dcda939511f563b8432d8cf6ac41130f01c45c24a14e4dbb30b446f5913fa541a3cd2b833a64256f1e1460a5ee560c3ce800cb04205e10" },
                { "de", "430831e106db9ae3cc9aa9d2c0f3480cdda2017ac8833188cd22057b13b21612ad1a27ec5ed2b75589d5e64f33d54f56507f40e4d34737c90346a0b484270a9f" },
                { "dsb", "208093b7180a4925717846c83cae4f866f8da0e7959129d4fbaafc4e7634ae4f9face653da2730e4ac3e6da4408746f8a749f309061fe3a70fadf6c7ffd41bf0" },
                { "el", "09a75d5edef490a219c27777e0bc28e0ab59d6a7d807f8cd9b5f7582ec17df7af664612604e10b606874da1687d71b1facfc23ac1f79d3cfb82fdf867d33896d" },
                { "en-CA", "9412ca3134517668562741ecac3d3d8ca5b88ed150f01941ec5a89df1375bf3b98b51f029aa8eca44aa43c0c505956c9ca0e13d861bb897f6740f43562f163c1" },
                { "en-GB", "e6a2d4d9832fcba385986032b544d24a94bbb461def6fe83a976aca886741a7e58096e59d18ca780d33e6632716c6e302f9c8467d2d58ab68c864998baf9b9cd" },
                { "en-US", "cf84f5ac4e6ab7e7301b8a522bbd8262d3d4ab726a330d5a4a0b728ddfa43c9677f35a5a4f009a0ec0de94f21b7ffdb45115d35eb23f69efb56de03d85d30745" },
                { "eo", "24a86d1b17a0327d2d4476662fc4c4319fefb0d4e802a616ed396b1344d3af0e5737916cbb694338672a51edac4131b5143f029e420377e7119d9996566a2af4" },
                { "es-AR", "8f91d615aa0e3ed21347f7d6bf782f1975fa08b10c8eb951656a247c90f18a640370cf7afbc058b4b6b4c0b0ca9d4a3c176b979d874c12eaf69e469d317fbdbe" },
                { "es-CL", "c6b6ca3d75f8bf822fe17eeca61171c25aa92c17f0da81fa1e007cde0287d639ff08388cb54e0ad3da1e8a406a222822c5318ed681ceb4fad166d0e01b0dafd3" },
                { "es-ES", "cf63ba4d1495ef5468ba84ebd0ae59d482b01a532486dfb484ad5e98f2e1b1a5ecd37391281442c56166252248d888d4842e696b1b5ed48f5aa0fbdb042dd610" },
                { "es-MX", "4e94d3db2a10c99110708361f0bb6741d3c8f049b0137b525794b08c590090ed1fa826702ce5a5fb12e799aa94e95a8651318f1da80634fe5c2010de4a7d16a1" },
                { "et", "6f572fd5aab8e1b7e28dd3fe0ab881a56bb46ac8447335b0ba52f077f40a56a7b710ba20b6a0dd98c42f3970f02e1647523f1e0cbf91bc357973aa46b0980064" },
                { "eu", "31e1c4d7f3db797f50335f1c27d33f9d05d6fbd5d922aa0f5904f0d4bd3c8a76ceb1d0ab8ab7653afd86c047c9e27dad9b14b7ef4af17a8c234eb4bd320e5c9c" },
                { "fa", "9b31b73428dddfcf22dac9a809dbfd43823cb5db79bef31b88482ee67d091e247c4f52c7abc13e1fc6dbab7caff646301672da0033c5bf33c989f22cebcabaf8" },
                { "ff", "a5fe2ba264e2a5daac1baab178a7e77be674aa18a362160d6cdea6179388a82054f3ccd0c43c87a726a37d7fdc297167a9ceff4fa63fdef705915797ab73798f" },
                { "fi", "bf9b4c13e746adcd92e8a71489ef5d5c91d0c6a6f11bc283b4883e832193e7a8ba1df07b90107d4e9bfcc69d939986189c32dfdfcb4c848253214a6c9f856b9c" },
                { "fr", "c654096fa5de135655128a1af7d4817e379c8f3d81c157a66f452128255aaaa417b94eeefa0f9fcbb0e72eb90baeb609dcfaae682832c99d4e3005a61b63f7d6" },
                { "fur", "4e63c47b3d0d5f4945a3c1690cc2639c8c9b43e9e1bf3eab0c7a6ebfa078a42010984a08e789dc43c0591bd782dd78a1e4a04b66e533234558610e3ffba86d95" },
                { "fy-NL", "dc0bd334f298889786d7aeafb1777f921a8b88fd079b83c7085319d909621fb7603c3e6308b1372c1fd55e055b651f5ea459f437a649f450186369f494d593f9" },
                { "ga-IE", "5c9aeb63124629aa19f1917b28db7d7880a916e72f3889ee4834b7f1930785ac3b0b26d7166468886da2855dc86c8356fdc7359202998a023d151e9a61912d99" },
                { "gd", "18aad2356eece701993f4759bb614aa222360b61a0dcb62c0932640509744411344decbcef841987bfdd1648b2c086097bba7a06b11f92c582a8ad88dd4bdf4c" },
                { "gl", "f974e93d86d73b5ae7207b7ae42b3b90137fee5621b222d0a45e0dbda94787f80edf784235776b1b510916b92a11989c558a595807a409deaa5293c8a2a0c924" },
                { "gn", "b4c21f16083022bb351bcbcbc456afa9797492078e0f449747b35371b6b6a239f3640669494ec0fad4d342755dbfc124fc65571e08eba8baa56d7c3db72ed46e" },
                { "gu-IN", "e4c62ea4c823b085ee0b4c5f71c50069447dfe7618f86a5ec227b69124f7e83db002431d2a9acbe5efdae4b2c9e39c5441612a35befb87774cebaf26823d6fb2" },
                { "he", "8779ab06e734916ccccf26766f87daabe450855d54ec4a22ae95a3d8d5ceb8182d8cfa9ca5da3766bc5e821e2940ecbf6518651705470bd64c22180f22b8824f" },
                { "hi-IN", "cf14678e70a2df3a67e03e4ea91129279c7ec36e453affb7d32609b5e38ac509efb19e034771fdc0a3c1c4d6ae77227149adc828b1d072ed064a143ec568ebf6" },
                { "hr", "941cc068f388f379c042532a952c28aad420e7a860f7f8f8d63b5e0979e92904ef3f1651e33625a1fa7c5d8e30813ddf35f171c042630e1547dc96fe5a6caf5d" },
                { "hsb", "bcc063ef0366716d5e7a38f2634f94a516f2c2cddec53085b32cb0652ad973f1e2b70df59ee118dab7d08be4e9d83579e0438a04ce4853bb30af837cfede703a" },
                { "hu", "2becc65434d70c44ea020763553732bca7a78cca6a9944a26d86c15cf1cae33b632d150c051abb28af7bf8c7b85d2720cadef6a259826bebe33812e319b3d36b" },
                { "hy-AM", "c91e5e60b558bff0ec0039e2a91f4ec9205504086041d34b50e8ac2db021d7bfcd840d4a7be08e7ebcce84df99da3e1938e2211618d898447e2b7fa03394751c" },
                { "ia", "c3f3b6bc310e7dcc346a81498563e13d189431e7e9c74247882727ba42539a298758b047e3bfaf316d9b8ed7c292ec5186e12a56a193405c642c9a3a9ce95edf" },
                { "id", "05813d489c8dc6ccb42f2b052c1b68fd1998f3d88406de00b476cb0a704a62d5d1a006f07931fd3ebbd489c0bd4ff9b24c3a09d6c5429dbb0fb3eb649d26fc06" },
                { "is", "e198cb28860938d9208dafef8480d61cb882bdb483c449f8bf3d7dc2e8371b963200853e13198cb8fd85091413384f9c491bc52d7230cefdbef701a593dacea5" },
                { "it", "3157f981d23f6796ddb6d7c63c5c10ba0e2a8666c47a5ddc7e3724a00ecd093cae3705e6e85ac655c327b7ea118ccf1813a18fb4b62d9aab6ab4a1cdede828da" },
                { "ja", "36f84d62f441efd2f5058151c48c3cc1095f04a2d82d14543d72e3e87b38befa589d7c6c940bfd71f120641f0dd38a9f43fce3441968540461117d32be009982" },
                { "ka", "8ff36dce608f9a2419e939d01bb5ccd581c26d39e52c3aa645c321c2919864a075bb95d244eae22c4e553457ab1d0d6865a942166ab4cf744b2bb1bb9f3d8957" },
                { "kab", "cc0cbd0c5338c5553c9bcee23d4e82f6090c14ea9362d32aca5f2630d84973eb41c2ae9000fe171f1b2d8e4eb115d90558ba053bf3e0ea4594bf3ae895b1ba26" },
                { "kk", "f17eb5350374497498d0624ab66fb6100aebf104ac826617c26756585877b1d0247c94dd8f2e5e185ee62c56569ec83a45599f9bad025952e23c5c69b3c41fe8" },
                { "km", "bde9666bad031c46fb1c9d8da2e739546f6cfbc26ced705d4fc54cee1a94ba26dff300a2cee66199dc2625f42a9f9dd579181acdd38fec8ceb29c97c2d93abff" },
                { "kn", "790ba97cd46cdd06314ef9ddacd351036a0b6c384f3d9d384f815c9dc041c2f78e5fa27f2db5f22ec82fb58d5114cd483f01ee72e9c9e0bf5da08bb1ebfc62ce" },
                { "ko", "be13047067815ab3536a668d1318deacc44988aa4d8e72200482d92b774fd09f0362343f2dd6a9f6fd87622e3c090e8e48546f505b9d4f28e09d1630e0b3bcf2" },
                { "lij", "f13eb55e3f4d1834c2738d8c15eca6ac401436d793afa80c71c2777a5080230b6560d8eead52732ba30def85ae32c488d94c6ec748c67989eeb216b17af7b76a" },
                { "lt", "145fd82cc723069d7a8fb30126ea9c61092717e514d7686e88712d43d720eddd4a006956b199d41e8e00605353091383f11eee8bb14769434c52edac61d23eec" },
                { "lv", "2292f7346820babfce7af61579306213c624e273ea9bb40946671491b4b8fcf1b998069e9fbe43571b1e565fc45c40695466ae25d3a7085e5c8ed6fc72d751f1" },
                { "mk", "9054efd58237e2d29e7a74d04e66d56bdf09e380684bcb8177d162dfc1bad2517a9b1d452d169f9790920e0e7e548450bab3422287463b6a4860bd7b15651565" },
                { "mr", "a07ca2a91d1d9527ddcc78732ba53ab225205066832f97b212e54ba7c45822fae463a17d08aa73d617a32e6de7eb9c5004ec5bbf1f1eed095417813858ec18b9" },
                { "ms", "fce71ebb65664c0a67f44116745a1a4315d6dd28fe731c58c5bb5db0059c078fe8270f17dab96ec3bba779542953e6cab432008e6573b26da5b834aafa06bd8a" },
                { "my", "1026c760fa24883e82f8d9352c1dc6e49dff90980c52d3af63bb72b7645e5bc851ee066436c49cb9ad2edc9ea56c73be283baaf0fa5cbddcbf00120e794dea74" },
                { "nb-NO", "7c2b00e166db13241bec996cd9718fc9a144cd98d76e7ca245bc7aa173ea3064fa971735ce03785da747c359308571a4b30229d0b6e6b69d225ca45c42c79836" },
                { "ne-NP", "057fd3ef611ad56c3758672439a0a92fa03b9ec3e5385264ac33eb2857069a458039e3fedeb63bacf60a9926f9872333a06ed434c518a8dd49f02fdd9df33230" },
                { "nl", "12548adaa6b7aba89c916303354c8ced264304ef54be8ae4fae818adeb6e5f87801e0f94b5e9008b78921a4bbcf98c98ebd1287fa5d396abdd12fda9a5957806" },
                { "nn-NO", "504d35c3dd5cfc55ccf9cdd8ecd421a3b811fa90b31a61d36647fc46e900a26e82ae282ee2fd1a003616cbdc8aad157527999ed23e0f3698b9136a5394ce01eb" },
                { "oc", "d8af2fd99bdaa2c2245cccbc2cb2a3b866538bba59b31a4279f416c871787bec84e0cc8c31673853bc4b4530132d5bedb667a020489624f8115d73e0929b050c" },
                { "pa-IN", "8daacb58e4ccf9fff3d4ba9b896e0f9f0a874bc772baa957943096f6eba6eefcd5f39e5c3fe9a45088b9ab5c4071c271051376a318187ac47df8d68ef16b8cb4" },
                { "pl", "1e4f0494af121a364af068ee91ec1e97ea140b9862035b9db54400bdec8be664252f6218c5de8d8268f489a5bcfd2044a606c0cf287fd4de0d503636dbcbdbbd" },
                { "pt-BR", "0464e9fe5e34ba3e69c9f4a4a3364275b796056287480c78b4fc07ff7ed6bdcb523a7b1118bcaca390153a00c54f8ae9a66799a89c4685c4e90c3a4da4295386" },
                { "pt-PT", "5ebfb7636801f690a52fdd773c0c1add9b5a6753e49b102561d3de85ccc651c9d1188c946d6bb31b7a1b6a3674bc3bc4f956a5f87f7afc7063e8a17ac10ec01f" },
                { "rm", "12bc2fba25371e1b054a2a3ca0f63176cbce769aeec98413e69e3256328be98c4ad47ebf5b8b93ef57efc876a23329182cc5899511017ac091366c728eb2275e" },
                { "ro", "2610056c858dae819021db784a69233eaaf6d21d2730452ee719725f4ac5481b03f773cc5af14128e56c4e34c328e51c43c4df317c8ec13bf093da5c8a3e39d6" },
                { "ru", "973d5cf2d1ba0e8e8cd97334df7a1b215026ed96eadf4add8bda0e8d01f7b020c9841440a0cb4e7de1ddc19761ad0eabc3c91d3fc9744c1759ff1047db60f4ab" },
                { "sat", "9f08f8a440daddff9ba2b01df38d00cdb9144b3c9da26f3c13a009eba39de3f82766e3e74d1a9c288fb28401024ee97f3b286f14acda0bc449117d8cb1e8cd01" },
                { "sc", "d3ac048bdd53eafcb414f709b8f90788d6bc931d0789339e2735fa00a7bdfe381000535274cc2be0aed587e1e34f713505246c4b0ef857f43051a2a5edc7d52e" },
                { "sco", "a43a7d8ee6c9514fdcb9c7bfef846d04401a399aa3259d7e0d887a97f9acd6bd1ce58cf35047a860b4b52e64e540723e0199dc4ef6c0fd60a675f9533e170b99" },
                { "si", "2445e776b4ffa908cf18b29f2288dab011620a3e10e3377b2f95f570aa26484f6bdacbd299aad23ba4174ea24a5c91f9d89365621fe76c539ed55a7811438035" },
                { "sk", "4c625726a25a70b7fbc46a64e1c381253dcdbb99c0f4b6375372ae96187fe8c2bad819dd4eca17b8bcba8964b2d75ff269cd3415d19144fc43edadecdd59d962" },
                { "skr", "9b222ac60577dcaed75f50f4a58f4ad8cbf1da6b85a2e4f8151f5e10307887c72efaa3d6c4b620cbdab4489d6d64b9c71ca4798faaf9b5d507504889ad103584" },
                { "sl", "ae72dc82c9cc03a26eb022512859a4e30e1f1c661fbf1e646672543cf6b16f417f6dc17171c1f99de0e41adef1e7af76cae3f0da084da50ec8d786007e750822" },
                { "son", "c535cd06d58550ed657956f8c0595d141349130ef45cca05f7394362bb71a0001f1a32e597512c656dd0ad9844cbfcc4485ddcad4f9c3bfdd52d7822ae664b56" },
                { "sq", "892708b81772314d3d648beedcd7f328e1cb257090b3aee633bf817301c5f18938e83f9a422fa46a70bb571822ea94972423140b00ed951cd985d640fa072e18" },
                { "sr", "5ca421d37b5750022e5400273225006c1e248dc811675e3aae359111c9f1dd631cb1f94b856a57e7c4e271021e05ad7ae2f1f9952eab1e45de5cca20a032e3cd" },
                { "sv-SE", "9cd69034c0112630623576cfd288b8bb35cb80164e284b9746f5d1a7409c85ca1f5273880faa003410c70a3e2c2ef31fa7853a796f5ce84069d092d39c34d315" },
                { "szl", "96f895a63218c089b99f1646778bcfc8fb33b41757367acf08afdbca7773a18e0890ad5c24c16e3eeb2ed369188d51dbf8b804ce9b33862ffd6330cc11a62fe0" },
                { "ta", "98fc01136c69a16282c9ac39cfaf4670875974fe0c73de8013d786e2e2f797e93757c39b7813e00d9dc5e07f4fc7342602791b75651543aa3b50531ab33162cb" },
                { "te", "58e62eae9c803ca9d944c8bdadc48ede68cec9a53453e2d941c6b05d816026ecfab294b6b22c53eaf1e092c52bb68f38c4729ad528567265b526de6ff9e0cde6" },
                { "tg", "ad69e1740eabc2ba1d24fb8db90799fb559e18964af2b36e3f6ffbea390a7b4ca2933b1bc753e18a018ed9c228edf0c4e00b1d562c5db7fe69455fdcc89f46a6" },
                { "th", "04c0eb042dc2bd4725e6cdb494907f583819086b4f577883bd1cf76974315fd3c5a5f41e447d0a060b09bbc0e27817de0b53a53830c480a5720d58d7853528fc" },
                { "tl", "5d03f525fa2818fb7f2a0600fa9e72b81016b6bd68c84476d1b5ca6d37804901cc9aea2127c7b7c7de4d6027cfb078f12a47d850fdf9a2b0ea1fd7c1a8df323e" },
                { "tr", "858c6d973352bec1309080bd62bb38aeb1b980f823881e1667404bcce5507f086f4c5f7ffbd555a7db60dd28d4ff721bbb9ab6265789eaaaa275d40b02bfe97c" },
                { "trs", "07f2395bf398f50a1f399460a927cf134576a80e7c7d03e1baf060d11ec97252c19eae76999230aa028e382f59ebf410964d1450c4126b70660567b3508f2dad" },
                { "uk", "ec775e890bcf0095d4f2bca84182cb3316cf911f30f4917baf71386908651b871a0546afd0d6f7412c6fe816943ab6e1fc524de2997478583a0b6cfff3afd82a" },
                { "ur", "63708f625df5dd9580b02eb8c5b51087d1192d36d21475beb08ac2f3cc8e103557347ff3a0fce184e5b32896eb0ac33783f246cbbb1bd5996d22db49765f9d82" },
                { "uz", "1bcbf7727524f05b01a513df75d7261357b7b70663403934b2d654c5c6c81e598f94685f5f14c94a50c1c6ad1cabb839d8d3878668fa40b233871c93b03098bb" },
                { "vi", "04d461f33dec7e5d871330d5b483b6c2867e66c084711648ea99d2f785e125a5a12c0ac199898738a888cb0c2c1123cb600203a36724ea12828328b41138fced" },
                { "xh", "13da64cafafd6585559e0912de58f0b66dd50b4e100353db94fde6597dadcd349f135bafec486c97af84b3960f41cacdf30dca9dee9938e7da3eed2f77ffbf62" },
                { "zh-CN", "461b3f719c1909f8bc0739e9ddd0d37769ec22644b89964b3d5ac562a1f59e36125dfd9ad0a445ffcac8ec21229488822966ab34c721df03a3bb502c7f251589" },
                { "zh-TW", "bc0cf8af211032c5638750ad58b47560fcc60d08ab37226aff5f0295a46b4e9721d9f72cfca20ee4a07612668f9e7fcffb48256ec7e3d13bb7923873c6a13b2b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/156.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "06c0c5a70b19f75c2c346332e8c6a2ad57d52e202f2b03f163281f0d7843b02527e28d5a2eaea5331c2dc5b504091452d498083157d95f0feec54700213a61bc" },
                { "af", "3443ecb68c3217a55aba2f57d9b2ff0bad9349ff509a71a8ed8d86444acf7fbc2be83b8696b37b7418d9f07bb996699d42dd6772539e8c3b89d4fb77a1162b1d" },
                { "an", "b5bfc6dad852cb1af0e3e502f9ec6fd4cdf19fbe98e1b4edd85b140d2ebc6d871c89d3c6ec41424b22050b60dc98b8b51fe7b4242355403070134d6b5b0c4d62" },
                { "ar", "9561c7e56bdae107ae83a0b6cd1307537f4f999941a6d62e14ce473e750e619bb9dabf28e527559f7b1a3e34110acdfaa3431976541402a0d4e71c815042f4c5" },
                { "ast", "b241413ed876f3bd3125a01a137fc95d1e1de6e0765ff2cd4d6b68d07b35c130afe87ebc1bc023526bde9f5adba585e86a0a71bae81823c1269dc876b23c99e3" },
                { "az", "5abe1aab78d2d4d00170f8db5ce444d10de43f2cfc03ed97cccfa1959fe9fc02e5b63437c1bd8742dd2eb144e83bd400921d1c9c1d6da72291afbcd7d9b299d5" },
                { "be", "a6b2f641c3f8358a871f3fc0294afe333bd493fd8cde6694685ea3f346312772004e1f343c6a19359c8193ee84890691a67dc65629a822d93cfc682b9b542ac3" },
                { "bg", "4d4f97a3562b0c9df6f6b0ae760005855eae2e8f0bc15a7f866de8f78a2d8f98a40c48fb81c1013a8f092f591ddbbf9ffc0254e6d4d572c364f78c8464e9de9c" },
                { "bn", "350a78285734c8af7d22eee7967533f31eaedcbd32f72f57d35cfeb96d4d758a85456f23141022d7086b33de342e2b203d129b7a38f9b47d68d42297a61aff73" },
                { "br", "b89633bde11da41a0f81e216cfeacf2ff725c1078cb60ccf9f6dbae4ac83865efa5ebf5abc62f40f620a3a423bc1f11ab84335c489fcb2052207545d21e38f71" },
                { "bs", "f227b6cee330f12c5c0b28586f2421012ec7373a15329bcd9b79eeb1fb6fb778e650698b15c1e75e0c5a47b0b4e1ad7954a77817534c7f3bc33d2257b8db5908" },
                { "ca", "ec5ea00ab0faf55f63d0850e04dbd2a35dd32d9bab5e8dd372e6eb494441f8965279234db615ca814700755f3de9742e175347e07e992eb11db02f812e069242" },
                { "cak", "2b27950b3885b6080ef059aaeecdb59f0c1087ecd2a8a38fb4957e5c2d1baeaa076bd0ab99d355100f2b68bd005d082a8ed89e16b6498073909da5ed78f458cd" },
                { "cs", "700b64b16329120e2cdcea5ae6d43a263bbcdf32aa097a26602e7696bf688a41236ba236d09d815fe68fad1d63a3b7f2af3ed11e734a75c464152e6b02f1f50b" },
                { "cy", "dd65bc6203b86374f47d2d54f8ac811f7d14fbf6a851327ed7027e7edba269368bd76092759531d92da5e01da1750603ed572e6aa244b60eaa1857a4b95bcbf1" },
                { "da", "ebebce93ed5bc2d7efe561b2317cd55f76407ae6a046f6eb03957261eb29c8ac7ba5bf4be8075eb43247c8f587751b009b89a67249cfee9dac84cae98a792841" },
                { "de", "01dda386e2807b6b6958bcdd8885734f84fc6ea8b2519fba74a72ff81812751921f11d23f01846b6053efff9ee2a9186113f60d2b4cc5852e8369b5a4e68c077" },
                { "dsb", "e10de55cd4594f30278a3bc7ffbd533f360d975582255aaf7a8269f093368c3967937ab15443e628dd338bf71d4b4cab46da57759a3b1112d6a7c07454e9cc17" },
                { "el", "82e051cb76f97fd666c889900c3cc10d897035f72b4fefe3c335790f6f669e8d6c1691c290d31325b7442eed0b034f24841f734155d05b964b9a11b97e2a4e30" },
                { "en-CA", "16d533d7dd708b72eac0c314c2272126df8923cd678a39eeb9a7c2e73bdfd31ae7c8f3ebf017445e0a06d8bcd76ed47ebd7a8522750572c1ce25785a6e4219f2" },
                { "en-GB", "28d55e07e1dc8bd95fff42cb1d3f496be6eb48b5c36b7bcb36506b423fb4121a94da908cba945f7c4924fcadf008369ab3fcc5ba76f11c7b5b11f1b3c483a0de" },
                { "en-US", "8358a7fcb6e8168f9344d137fec05589e278884a05e3e4d60ba71042b7570366daaffc2de4e69f48f32e7669dadc5e806daf73b04f62fcf540b1fd2b1a969913" },
                { "eo", "3a62b07f628207f270edabf16a52c593d9c822132301c985d8a67ed9eba73bf3495a5483470f58c77662f641b28aa33a71cba5234b0740a5721933ab655a5361" },
                { "es-AR", "2d0ce9a7a30ef392f22ed788f14046aab521133db36d285669e1f4f418d7ec3c67246b3bbd9f3b8a5645c8f3e069a24d478ee47a9b9a1236e55b4ac27033b612" },
                { "es-CL", "755f10d57ffacfc6f40d60a4eda1186fdf4a3bfa09a8d5c7ebb4ab419ce604e692c4426da17d4215bef11eeb9a1745de638ff4c3884024c42c664011a12933d3" },
                { "es-ES", "a0bdd03aa64d372f081da28e5c0bc0413d7578616742a60a2211228822ec5a9095c7207650bcf8d64f53b8e7fb05c1bc5b8e371c7c7ccd9121bd93e346ac1556" },
                { "es-MX", "3414f044f13a1b870d9f88a5f086696fc27dee3c1760dca6e8eda2110fcc056ff4f8523ccae23c8841d26e1595084537269ed530abee40c62c41688092091091" },
                { "et", "743f4475651898c7180051245b10dc43baeb74de9b87528948f8bf41fde865d99ff564fc45087e7a0af19fd2ca49f6a5168d25d349e1b4d2284b9aba6c1b7494" },
                { "eu", "c0a70036ff58595369020ddf34014561b0cd14112f60185743f2b52edcf09e71ebbdb62e386315792fde9c517adcd0771316f908b6aaf07879ca3ec0f8c1630e" },
                { "fa", "cc24268c9ba6694814af49d563b327d2ac26abaf0803175035451d5362e59372612f0ffd8c6e3e60c29e087ad18911e074b9589af1e5aa365482c1d4a030cbcf" },
                { "ff", "617403319f7b926e99bff037bf76181fe425f32688265f3cb687b6fa22589242920a0cc3f4a271455c89414bd43811e295eafcbab21acae081a1b6b5e4b0ae32" },
                { "fi", "a45c41947ad4ccebbe7c6d4d1ee6f630b688b8b48e18679b7519234e4f159da730bd4f1b392d0e1a6867dbd32fbe62f4154778d5d715487b9ba717357b7def8a" },
                { "fr", "af1a63fbb75c8fbab59df2f032b101d2de24c1541b9331ad2a4492be6edbcb5c364b86acf32e2636dfc9a1a4b63fedd374f8658a60fd12e4dec2b77dcf65fec7" },
                { "fur", "c253599b94c9d6e4b2331dd4f1003729fc178560532414b8c60fc77d8a1c9ce3e2080d5e351f9ec4c11db00c07201cc929dda6ae369023a316dbe4fa092ac0b8" },
                { "fy-NL", "2c140902c22e6d43de7898f6a03f166e09e4cdcb0421e4a6deccf3a81b605a561c7d6b4e444b4d5de8e5246e412c9f22924a7541eccbdeff053e01eea3640412" },
                { "ga-IE", "12611435e0571a46bf0aa136af184c8457c4259bfb4e87c17520d6f8016ddff221605adc206245d266d026031512792278755e2a60b1aefb1cfba8126a031cbc" },
                { "gd", "9b8c83eb4b46770b5a987cc08f99e0c4505308dba871a9fcbcc2a9220075ef02a738418fd0136871e196b910692541d4a3e04639a751a30275d16e483a6f91d9" },
                { "gl", "a39914329575b86258686ea4ba157123f7026bf92241f548812e9e6faf5502d538d06bdf385fe834c296f9049929620d0c8306d041eda866df3c328a9454de77" },
                { "gn", "e08b0aace1fffae49a599d0cbdbd26fdac0c546427b63626e1d1715913a14e4bb716108c27bb10456e73d14f7f7a67def798b3f8b11f33194de1440742153af5" },
                { "gu-IN", "65e54948524254d86ccc2477477b2c53d025b86076602ac4dc0799e338bb6f07a22600d72962088a7a50e53473296c149498f632d4d6ac6bb23f876edbfedd60" },
                { "he", "91016cbdc3a39216cb618d2e17fb0d33910427e051f41d09f7e728e0e57ad58e5e1acd87c5b50aee8ab7112e1adc85768e4c9a5c8ae2f8c31bf7a4ec73c62f0a" },
                { "hi-IN", "97e8ea1a0159d0e084f47cfe0e072c834174982e7847dc1d91fc7857817de46d3c2253ab50c4203e80384a7dedad8e3d77af241e1f97fa203504fb804ee0f18f" },
                { "hr", "06198b2c61531afa523f7ed7c3dbc1471780fa33989264738243810a01baf2eb6aa59f5ab542156e2c6963b0ee1ce94cf9b12e2a16b3d0667fe621326965bded" },
                { "hsb", "82d9b1a602be3d1ff9743fa59f1dbc944c6eb691807aa885f0a4c718c155cf1879a672a4e03eee50eb361b63d74c58901ab19a4866d8c10a4ad2f8c3db3541d1" },
                { "hu", "08f0909f7366062012a8a17ebd43c690ad3dcf28c165a68abeffc1b3056c52050799c49e9223f3f2f55732e9aac9215fd9bafa10770da90401884e38fd4f236d" },
                { "hy-AM", "437b8ab2009a77404389dc18cb645e88340359d04c9d8e22bb0fd4d604c826d9f8fd1007b5094d146bfb2a9125cb807bd26371225a820b0bd2495889f5aa0893" },
                { "ia", "ff22f96f8907edd36d2cec0e27762d93f2b2157147e44a051962289c75a26649f38005589dd7f6808097ad3db475e3e3bd4797af4dc6b45d72e1cf7f503ce8d4" },
                { "id", "33152394ad15274f77ee46003b52b4ab86c59889cdce43ea4d99517ada98cb0e2b5c0e4bb147bf6d30f380e12fbef3e9c76928ede23bcc378eea0181efeebf5a" },
                { "is", "4050ef991976ff1981aab57c1085bac538df12c3f67ba8b85849f7e885f41a0808f6dc19ecf8e6478c2f9d8ce27f95d1779bbbf7163d24bce95fc6efc5fa42fb" },
                { "it", "a54dc1cfa3d00c8907082c7a4bb568d4b7f0754bf869ceeced1dd55c7ae5facf17af135775d19d56f613f0d343c5ca59499ec1d1c00ec6c30185fb9f86f93bc2" },
                { "ja", "1d07d591b3bdee6ee5dc5b4440727c97f9941ae55127dbae7767ceb64221a26e50826df63af1c1009f5166177bad422788569e87905bb4809e5cd5cd25336136" },
                { "ka", "0dd90710c0c41351b085ee8e67f2971b1c33959a9aa59841341c20e714280c29615b589d367055352330088a8a41aafe3b75a6ab10d5715fbf6ffc22e39e54f7" },
                { "kab", "0d6bdc69591b6b92b0be388c784a9e2c3b41b1775d0b945315b3332c840ff0329bbf15f4c62da583270ce0c65ee08d6fa66d3747e9d966520960addc104d21c6" },
                { "kk", "104518349dca0065b3f4fd83e339a842738174b1dd1bb46e2b9ee534b1d0b9c60adf87b7b9fe9d5af8fb15d8f50ed3678042ab7e84a04258b0050f590e8d630c" },
                { "km", "0158595248c973cee694e6fe03b0fa28bfe2f1139f9b7db26aea8a6b559037778a8965ee91c43726bfa844f2c87a2b98bb5adbcfa1c958de909fcced8b37921b" },
                { "kn", "913dfd2a3bded0003d8e652adb3362a4ad4711d4f92d0f628383ba33de6a127ae8af822479cc290c1a706092ba80f23010dd72dac062afdc8172cbb1a7090de9" },
                { "ko", "e18f4b01e8991f6d7259bebb5393f3cb16a426bb8fb37df2593ec126a5d1f9255925fa532d5fe905ea4b6dc9ba8bdcb28c87fc950be7ccc13ff4161e6a095aed" },
                { "lij", "8b9cb8b320b3204f2feb6acca0110827f5307fc758a987f93b25d9395e5f7099f30c8031af324c0dec5970fe570da0f405dea03e13a8d9651f27de49c4270ef5" },
                { "lt", "605a6cd0eb5d3bddd3326419e69fe14526c22caae70aa2ed564c10c0c7f890fd2a6125a4226b2dda71b317be44e402d060ae405379156efcb9c34e528029f665" },
                { "lv", "398bb6cb51936fed90ff2e7188bfe0bed54eaa4cae1df5d1d3ba5ca3dc0929912600a42536c01517e0c5ff1b37709ac753390f6d9a30373adb39b8cb1ad1a354" },
                { "mk", "0a40da95cfadd753fceaa44cc146c31d4c8c43031d05226235a5886833995f10d8b21b1f42ded01b23736e00fe6c0269a097fb66065fee00071a7473d2c7a949" },
                { "mr", "5b82a80c1e471079d83cdcb68bde73785e211a51666bdf2788a2f766193732ed9d988848783fe54fd0a5ac3afd1523ef9ae5909c7774b36b2c416de17abadb18" },
                { "ms", "c14d18ee707f4ba253acdcdf0b3cb71bee2fd69b2e474cac454099ecd33af94ce796214d64ebfcee461aec3f4101125b6777c14f4ad40b7f3d52c8e5719ed935" },
                { "my", "b7f99cbc7b8a9f56c278136e9ace1702a52c4eafaf078f3d7fa812c757c4fa8a03dcb2856ed2035b319f4d6de4c43a675041cca841901602a4efa69208788dac" },
                { "nb-NO", "4165808fd96340f0ddb112b2775631430bb7b58a5fbff4bb22de65d47ee206abd24c8fa3db1f96568230a4e243ebf3279a620bad7412656701b14c73ca96d5f7" },
                { "ne-NP", "ee428b6a359d77bf7219381404449ddb789abee69f3222d025d022cb07849a29f8aa2a5b6b2c68d6ec8df4e045692c06abc3d6a8d5ac822d2a3e9f695184673e" },
                { "nl", "80d938d95a1f8f802e657c7293b179d2aa44514491199502189d88786c0c3a12c6e303c9cbc94e9434e1cd92dbe1d68757c571fb3f3d11efd12ed53b7eb81235" },
                { "nn-NO", "c8ea32b18ae47ec8770ba1d074d8e51245f833934efce7746df1516c36a4de80e7bac823f595df905cbe67f339fb8ef83852f584f484826e95a28b09918208a4" },
                { "oc", "bba43aa1420ad6069b8164f95432740c6aa4a4799489a94d6f8ae7c79e9eaf8dc558ed79ccc7b5e156a7ea5c3432fb0f52d658cdaa6702079e069dbcfe8f99be" },
                { "pa-IN", "41e30c062910b4b882b599aeeb88dec3250df8fbc48c9d62aac1ed16a300b794e423becc937a3a023f2e467a89a82c89226af841bdd351290cc5f702727d4611" },
                { "pl", "10818e4f2b5adba7c30cdd0f3bd7f3d5f41f7616c2a58c91ea36bdd591289118320fc92af24f733a7327e9022e9b27571adca4b77eced7eaa2d5c424b09b46ee" },
                { "pt-BR", "6e70b779a5074b8428cddd10af9b9b002ea8ddb67d4b8b4a294242185eae8b099674c31c872985e40c87b772d6967baddf78b5d7e6b4711d85c7448e085649e7" },
                { "pt-PT", "f5e6f5f9fed6b7ee5f161cabe7c7805c675f6b365f7146a836cd1b91641ffeaa1e5be2c584ff2d8fd6b1578c62afe1cf82063925d529a1cdca8ed3ddf0ff06d9" },
                { "rm", "2d71bede680f72c7f1be0a4960746d7846bcf751566064af2680afd94f9392520989d9746c39a1776aee234b52a21c5b6b5b112557164b1ae947beba62957970" },
                { "ro", "db4ce41f806705132c9d8fa3d3c55bd4abe90de1689450cd59be8760e53d0dc301a2c5a8e8284ba6d26ce3499a4e5a802a78c9dd914f7f62a90454e781ea589d" },
                { "ru", "41afd7c85aa779c9115dae0d1f8ed086d598c797feed98286bffabe291aba4c5c914a7378fc89765adc7d4d4351d92ee66ab290c02d2b71fc5b35b84a1901bac" },
                { "sat", "44150a2939e997357e392069e386d3a1ea354229367edb9c99c8e74ec52d613ec5c545d91f2521e85421bdbd0b37d7d3b09ed5eeb6a75dd391b39e275f755f8c" },
                { "sc", "92f468c0e807009a5d2177ec23cf2c99d41ee5a982b8fbac2a35af2e8eec3ba1dd0952f9b6894016fd80759f482b079ae0c642d2eb6db20d21cbb3b643c1157a" },
                { "sco", "9da452baed3672a33b64a95517c91eb1f40d48d9388db447947dc4db08fa5f4f003dd2413290c409ef1874b653281e7ded8b016595c5f76d62f6656f64e81bb7" },
                { "si", "0766f8d8ddc1d0966d7bbbd6334f9c5d5a2947a749a9a84aec5afe47faff33bff47411d50a1e343759bd33783856c67fc65902660d079cf81c99623c7649cca0" },
                { "sk", "39cc7ffa6b9b47d9f1146c2463628bbbb01cebf1797a257192e2c06182b14611becf1c8d6e9bb95a723e9e486cba62d2e555309428cf1271ace30b457527262e" },
                { "skr", "26e3ffd627451da757df4e93e565fd2774af2ae85d9dfba259f9a685c8f9cf1b67a96de0a50fceefa703a3c2be0cabf90293023c4562d618b0584b44e00681e8" },
                { "sl", "220a9684011fa6734cf59a681c421f05cb3dceebf89f20fd9f23d564edc22745b0ab7576c1d67201d95ec3a7302b64f5c710aa4dcbec7b8186413dc293e9a250" },
                { "son", "c450c724934afcbc764f32bd27beea40e46874bae15b7e45deb3b00402233e99a99d52f52f1bedf4457bb1deec83e35ff2702a9ef147843f5a011a503421d0ef" },
                { "sq", "543594b7edb3922ccfb491cfcaaaadb6652feb29c70af200a7063af2c6d18df9f3af3123c894dc8eb820e606f86e62722ecf4e97917d572335f7e94f5c7c1d99" },
                { "sr", "b4a9aa5d35d3c14662c107c4c060ed0a6818bb4cbb82995c8d98e904290647df0ee12956334a84ded98753af6c1cdc19891e5cc954a384e8f0cd8ea679a1901f" },
                { "sv-SE", "9fa22a53a7f955ca5c522860daf2fb2296ec4fb4f6df4f30b6feca8c770f5602b0393683be61eb5119a159cb10c0f578884be390ed79e6d1fa76d9a48bc7e90e" },
                { "szl", "73cbfa173c85e760f880163b55c8fe988e96df02a22693be3d3f066ef1b4b1de87dd985d3755c73cca906c7a820c24277c96232f2ea90efe436498276956e2d5" },
                { "ta", "9b762ce5672905141d73792c7df148b64df8cc50dbce05ab7933ac367e8c283a050e5c920988c4f0559eec60cc02f128baa2cc982b0684cf22e65bb8d26a7695" },
                { "te", "86c4211dd2b239507d6c2fd3afb7749fb6cc80f983a2944ac57a5e7ed1f9eaa8db9be8e2642cbd05d4cf55a64ddcda065b5caedc44d5c12d93a30854f5d18015" },
                { "tg", "30eceb3098e40119339411b346e1e682983f609101b223c32decb0dbc23fd1f62718ad43f1eeecceda61e978248f0e1aed81b1cc2dec311fd6addd940f138bfc" },
                { "th", "3479c7584258cab5e856827de74393c63feaedb5fde3fea277a4c28e0a4cc871ac8f13fa0bc227d4bfa88dd9ea8dd302493e125c74493323b21c9487ca948d65" },
                { "tl", "5aad4e80404c822475e380cb6b83544e026bff7d94b3c677fb7cbb98949972fad88eba2b3932c2fc09326a2f42fd07057bd95806ec70bd30d7e0ffcca378ad51" },
                { "tr", "28b9416789c41db49e2da189c342e6d9c1c7a6d8daa930f0c66ef8387fe2571e3953900bdcc56666d3ead3054d4dce0b5efd2e290d0d4a79beaa996e98d5c14d" },
                { "trs", "7dddd1ff96aef330c4550aab4a929a9990d10a7a5798830f73a49cb2e8ef6d93677218b75fe1a8e894c8603b607bd5bb6779186df3f9b391a6f1fd20968f904a" },
                { "uk", "0c41f1d44f5e9b81670a2b340959d0363f26b1718c078d30beec4c789e624dbd9314cc9e59a93a5c5a5504ac636e3db84212c4a6f8450e68abd8c96cbc247a97" },
                { "ur", "370bf4ab0973367c23a9798017575dd08274b26d15d25fddde5315eab56588b87146937b31eeb8f17c2021a5ce87f2fa48f35377e9b7f14fd3570f606b0db560" },
                { "uz", "085cae21f0663e4496bf32233e38087a582b73b3a5a4a5de347673b642ff9ca3036feb53f5e5c66adbcd9352a0bcdce72203d454e54d5c58a6446741b17e3fdf" },
                { "vi", "cf18411aa691659b0abd161f7280e16eedcfe9a1d74c2121f53d21e266031be3dfe70a620be50ca73423ca4d125e235f0ebb715a1af1a6b8683e30e52aa54b9b" },
                { "xh", "97d5f9f5305701962fdc889174d2393218f1a874ce3aacb572c015eb277ac6a09037e0d6e6104b0e2322039f93b6fd0e2eae9bf2490083cb04c40644481d4f34" },
                { "zh-CN", "3b604e7ecd93289393845f4caa6e1512b2e9c4d1d9daeb2cfeb18f317bc5bf6aae769baa77b6ac6c9c5cf48ab86da431ca757e407d41820ee45dd6e14d74f081" },
                { "zh-TW", "ea5193f7877b12dfe85f9526a0a94c92e26fd5bae59f5e6fd7677a9ff49b5c51b1463b783ffb4b4e7354a31caefcd8897dc8869bc19b7c9f8a530cb4e040294d" }
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
            const string knownVersion = "156.0";
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
