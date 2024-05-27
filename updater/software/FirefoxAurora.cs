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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "127.0b7";

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
            // https://ftp.mozilla.org/pub/devedition/releases/127.0b7/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "34d55432b398233789d7570edad8225a110ebf8305352339a027426cdbb552076e97b4edb2e312a6ffd649f2153c4aab69b312598fe601d1ca50f17f3796c461" },
                { "af", "d0e7a5778f6e3d3a256dbc0af02cdc86971eff12f2faa87b1a08b88d07b5832c571f2857eb9931fe58b7800b325ba40af23de40649f2396c51d54c2cc5af92fb" },
                { "an", "17a0a267e8b7bec0269ce2c5a35ba971a9397fd4dee58cd9ea2d9ce25915f88dd6b805a3900c9efb4fb016807622e7d3c5d8ee29a16db8dd96007382e4208cef" },
                { "ar", "f8fc4d458625e883e33f5b38bb2a749824a3e785c4b1d422ba8fb71b8341920c2b51806be91337583cb5466829ee96f58b491c373b42768882b5b4ba1b82ef81" },
                { "ast", "f61d23b882fef727204ddffc3f2b925b21bc1d618e3f2fae84e839974678f31834cdd999cc99e88d760a142a2804ee4cb95ea14f54656d5c1fa538f33f2b4ecc" },
                { "az", "c436a4751af8b0e50585f39c966a66d1eb2e492bd310354514c979849b703a5b46d500e638445911566e380b4dd61f35af1e41dd5f25186bbdb45481e1e35f19" },
                { "be", "d10517e6e9d69e377744f54b9dfc379a4ad2de24872e263e52b150af02165d99c0722ad9a045e21d7ca5cb23c30930bd4103e80c6e0df4bf07100ecf564be6a6" },
                { "bg", "cc5e233ee64f9b4ca9ab7852e5cc819669da7208cfdaa2481db76d74c1da2eb9631cf00582cece01dc08ea7f614536a504163d97274ca68db17e93b4a64943ba" },
                { "bn", "50545916d51faa1b66f0eeb875cd40f6b544ff202494f9945090afbac26238c11cee060332c3f3e23235143b8a3d6eb8d5ba88e76256a29961602947230efdd8" },
                { "br", "309a01eb9b0f3799f06f79ab9bdf162b2703f512d1957fdaa27f39150c8a47e789a345105dff45b1886e4641cd2dadfbdffd40f1de3ea200d3d1830fd00610ab" },
                { "bs", "c9a4bf3b8eb97c57a23f3ad4d535736821a40c40e264b2cc7d0e813525341b7efb23289b4b5143c2110392c40c315b1132940608df58e30be3ca9d302ff15e28" },
                { "ca", "1b9b02b3b70de6aca9f4f188605a26dcfa4886905b47d0068d87d53972a21af39f1b023cc20067aac7d2730d25a7b447f0017e3ee3cbf2872707f24a03c5f739" },
                { "cak", "e8f03ce2b6906c3db3eae38346faf36b9cba32a9696579e9eae5e8476286b1f43381f44539ca88218e9a1593b36487310c622d394c7f69814d70a0cbec628e1d" },
                { "cs", "7bd338044440f56e0f5ae6b77ca2fd78d569bac87f645f98d17b2e78945ae7b6868819df1308fcc7c6f47398d1c7eff7ef3279d04d683afefc0955269a7209e1" },
                { "cy", "78fea98542afa16c31defde24d39e1a96f79cc7ddb71a3a9495a85cecf81b5a9415219a2f5ef49be1e85454b93ee018a0d443a6a64daa9d217153c4b9523bc02" },
                { "da", "e8aa3812a626cc63fc67aa3791afec3f97c71dd93cf07237ae66296fd959aa51846d997c93922a4d66e3faf3bb02ed06088d24a202e0439fbe52b0ac6accfa0e" },
                { "de", "e45fb29ef4f65d2c4ed18866d455bd95e7d29d4752e3f3291cb101fdb66ede19e94a43568a3453f404f5ae84e64182ab857b604f752abd3dd1acdb6099e00d01" },
                { "dsb", "23e2d4088cce08665c520aa3d4a4b9b034fbccf0d62e48990f89f3d971cc4209b85d15b27b68a15772890255d41e234d7d87cb81cb948ce5e35ff62354bccf68" },
                { "el", "16d1107138033d919ae22b98be9c567b4f669c91108adb776f12b0778ff75d4be09cfd269ce4d39d7d6dc341f3ed437afc93dd8b7713289f70cd7e4d18e41aa2" },
                { "en-CA", "358ccf66b7c407625afc7ea5f4a91ce215eec14c29c85ae5fa4158639b95f8714e471450d18e56a1fef7e19b40cf3d1a170fa7a8b1a4a2e20aa6d452e454ab7a" },
                { "en-GB", "aab43d12ffe782f148a851e7a46e0c1196138586a00b324ffa55ee397ff9d60455d304de113ee7bf06f9d0f312abb72b5fb65f40dc85c0764d37cc212489b267" },
                { "en-US", "aa46edbf2c6f6211927deeba32bcae1935dc13c8a301fa60014efcb57db8f6832fb3b0564ee1ec2fc011cd997f1a490228f4049b6aa76760740b65fb11238d94" },
                { "eo", "eb6dce668f7721199134c98f2a3db92bb6c3227622975b495a7c657d88b0515996088a665c2d5c679b4f421c9fcf3a2175d0b34913f1a7f542bdd8d31fcf9cdb" },
                { "es-AR", "ccaa705b429d418b2f31d9d915ac816a08ca199a2f9d8e962e1ef0fea1fce49ce8ac4c8449c7ee292ea3a3605c769af60b5b5beb3bbc767fef0af20c79c7ad4c" },
                { "es-CL", "56dfffb1c49367d8fa0711b426ad8e24c392041957e199e8cdc7b691109364f3fde116f54418d0b8076c6cf4e552334d1909adfdd2cfc69aabfe32c3c778c496" },
                { "es-ES", "1a4eab84d4d2703d8ff07df3e7fdd2c5ba7737663f1cde69000dbc9476c02158f882dcef8c38f78ddaf37ffe946da1581d62e89df5245ec75dc05b4e2a203ead" },
                { "es-MX", "a2e4ac15ecb6ee9e493cc70133a93045a87e8a00c965d4f22c2245e2bf7b85cb85988a56a2fc85f9e615bb1aacc3a769f4d54f192b5a1d4f5b2fac446849d5fb" },
                { "et", "7daf5d446839a014e281b46a392f11843a9307bd25641fdc0ac4edeb442a752fb64367e4d9f4baf4a38306d43904d352dc00c54cde36a565fe224b5389b27bea" },
                { "eu", "fd94048564b2a1216303f9df3283ac42a3afc446b04d5210d0191269f4d89342a5448786553bed9237bce5b64ff0898ceb19b2d06331c898619c441e7a89f33f" },
                { "fa", "2df468a21866cae7c653c14e01f9a722f4ccb2ca51670a4b71b44d2297a3072c0a4cd614f051978d9b5f84aa6f2e2ed0b88a6c0a21d920617be696b0916cc939" },
                { "ff", "232238710ee19efc6fa6a22d9e4e2801ea888fc0acf7dd08d46b782c40368a09eeddcb491fde8da46fb36d310122e9c3548943c82b8e1ab743e714213c1b0649" },
                { "fi", "1da250d6e50603ba68f822b1e41e63b58be5a66bc9a2be4553570602bf51093743d814057142c7cb6f8ed04b24c259a985342b4718cf523357836a656e00d93f" },
                { "fr", "54565cc062bf2993f9c624c0bb974838e691c00065b91a9505fed982bc29b14511058bdac2818e5926a8fee1a21c030830b9a112932ee8929132139693903703" },
                { "fur", "906d5c97835209c86e805033acfe16f7b5b5ba92394a36613435b9bf450e6679c0e32d3fd3767183acf56def4bc7678443fc3ab6782ab070acdec7f6e4f35b75" },
                { "fy-NL", "05951b52a1d9587ecc5595d64f8cbfc9f543039e266092a36b7d41d16c4e8961c42d871d7592182029ea2500e3e3536958251b447cbb1958b1c37349fb7f7a3a" },
                { "ga-IE", "5833231b876e82b3028aa94fde35df4804fdc84cc01ed592e88ac58bde06d690daccadab1528362bd49acb9aba1f0d38293cbc9647e94c8c8ae714436ea94857" },
                { "gd", "92707b14baaa7ad892d46ad0cdae0948c2ef06b9620168a93480c0310918f583ce0991f7acf143c6a55b1e96229759e4f2b1c0927489178998c65b5d3b9bbeb6" },
                { "gl", "97a888d66a1298f77278677509de16bcc461d14c3935833c1c183d48ce738ad00ba1b99f623af59513cb188d5624bf40662467a04eaad5a53a6ee23bd7c6279a" },
                { "gn", "3ca5776fdf83e2b5bb13573ce52804cc1a5cc97d54cf27d1c3d782bd565f51c835a54668cc6a8d650f87578879f314bb110e010f4ef09e0e2c6c036759f85b7c" },
                { "gu-IN", "d2287a2faa4f3c73744a5ac1ee1ab08c23f654b870f29a4b20b6e1244f502d0612317a3826468ee3123c4c39bfed38dbf6effc62d7a9ee751fed909ad03e00bf" },
                { "he", "910203053a6f5a8307cf51c510cffb653b02450ca4bdc21b552ea4de135f27104ef1b613fa41e54d1c82d7bb4d89cc08a78067e673c7495e7c6cf7382737c5b8" },
                { "hi-IN", "8591285f195539a57dd46ddf42f611c977a110b3afc95afac8d69ae6af1491bda71bcfaea657f27f72d11d1b581b9d00389da6b4707d10337401f9fec460eca1" },
                { "hr", "4dfbb7cd5b494ce171e37193cdd702369d045d088c1be933d2b06e3c8ebaa077921ce3d54df360d5d6637af1c166fcfb8a15106cc80f7a776d9ea7333fbd8824" },
                { "hsb", "5d0c2c0fe4a04603fbcb15b92a668f499b0a220dba1475f39c66947ebf72476f8189fbdb8e0dbd11fcd39ee3ea8011b11ee070093e588799ed71271f16fb8f80" },
                { "hu", "d9c43e0f77791fd79caa8afd9a8c016ec274a9e99943a990b731ccafbf236f3f8bb0c01b014928bda937102790a92e42ed5ad4b4bd11b4e1d96be085f86500d2" },
                { "hy-AM", "89b9897484d01fc672d45e17c2ccf5ac2d6d0e8dca9290259e9593b369c0fa748ffec8476c259b1053e0a1e139f3cd1c4ee97e765358cb38f545b316f25d9cf9" },
                { "ia", "4124dafa08ea16bf58306e85a0994ed3307dcbd4b49ed593a433441e3c9bf3918dbfdf2de26214420475b40e4b74a160c01beae13e32e6332e240c5270b554c2" },
                { "id", "eed815e91b970012bfa5e2c60dfb3a763b87cadb18d628a93b805ff63b5b04c9460b0a04d3e60adc764cf674af86702b96d3573fa9b14ca251ef22269c5bfc0c" },
                { "is", "3d6c37e06bea3d0ac65cb1bb299f15aaa9a7a054cd10eec12c3dde423967d12629580c78007b87f005ce6c3752b3bcc3cfb03a5f1716cd21702aa598fb66ef5d" },
                { "it", "1d96eee85f1674231b36c76d40b546e04750364505be7f11bbf162f20ebcd3a65589c958b5b578eb26e08dfbda69ebd32ed31a691c5f73fdf962d055b5a515ce" },
                { "ja", "95e5812e6c8be8f35cad72847abeed099cbf0dd17e2a30fff1da47f029d1a230e4d59a5b8b99b3c9e58f0efd858ac18ef553b6e9627962b517d8ec7cfe73963a" },
                { "ka", "094aecf0ec303055e0e9bbbeae178f57c9bc3c9a33824f461a685ca0e85fde8b195b4f53bf395390a865fd400f7c83f2383d2231d6d5f245277defa7b5af8bcf" },
                { "kab", "db8cb294e7e31ce910d474cd3ee1db6915a4a10d8e071fd096bc4f28975cea040aabbe868fd568f4b46e0af2904e11d9118cef42c6a68ab50e80bb3cbff0336f" },
                { "kk", "ab9a065b3d5d5bfb65584fe1fb788a5e86c05b5a8c87ae2a72dee7d373bda692c7e55dc2882957a0e65f3f7929982104cb237542db99b5a4ac79e381906f6802" },
                { "km", "32079f61ea4313e54bccb9b7f3de1952a4eace8b0b5d9d7f523fc3f10529c0203019262fca4a670ebfe9882e2106fea29aa9843e085da099a22f4ed2917014f1" },
                { "kn", "1fbb19acaa489d2526c55d5b30e719d28b6fc13b4bc97d8e77327c10c3451f0aba9939e0283636bcc8c095ae7c85c6143f4925d26b85590ab41c89b954fa23ac" },
                { "ko", "647fcbceb5376dc4d637e2307b1b86727d3ab523e05c7d7b5aa2ff3b286d878aaa01e0bfb4b926bd3fb86210debef8aa248311551cb585ac30847990429891f8" },
                { "lij", "1856f7801633456b372c2527e53a076a76b3fa36d6c70b206086599025a75aba19afbc58ee0b02bafc54a276aec1a9be1f2df0119458e167ff5aa20564e37587" },
                { "lt", "93b0075fa1e814dca9a6788ae1cb9d79743f8f115dd258e675a05199342d718bd23840f8a09ac86e63a2ad5bc34f299e248a19c047bc6b649686623e06a19659" },
                { "lv", "817e5707add07ddf27e9f288ab59fff8ca0c22103e695b1d2bca014306e43ad358373e16e9471f65f724fbac41536a303c3968c6d4a045e0d34e08318ee0cb34" },
                { "mk", "ac278c8b362b5d167eee204ba84544fb2fdeffe3382ae1107a7627e9d79ad2f252a22827120c04ac73ca28cebedd1295848c21f192732786fbbed651a2c680d2" },
                { "mr", "d99749d17add388229c2e6ff0dac8daef958e99b1f36478a5c15196c48c169630af97deb4fcfdf411aceb44b169dc38153090cabc657c237c881be8522309272" },
                { "ms", "9a097c8eb5aa3e5464b2c2f3298bb10f6b480e8730cb0772cca95506a295f3adf958a268a101e12c5ea9145f441c931d783cc361f6b92e7b46467da1d5e6c3d4" },
                { "my", "32dff08dd0919cced57fd4223896c82278a5e229ba1a2b790c5d937177da94a66c0fc498f30b2e37cb2c23a7cb290f811e6adf6eec2763cbe620d302d8295e93" },
                { "nb-NO", "ae31bde3ea9e8b12b07548e0723cba962bef582971cabf21e22a133564a8907e0fa51d3d4b081e100d470db7109035389725757b91fdc36698ed251cf49d01df" },
                { "ne-NP", "91d0fce27f6b58ea9d9fa7158b7d02e8c4303119d36975e619cb212d2773d6f2209b7d880f10438d3914dbdbe4a5a914a77ea818e02de23253786934a57fb079" },
                { "nl", "80a6bd26c3b88a6a1a71c78f469446f47f877da9aaeb2e6af62bc390aa1430e1192b4d5a6268cca1b99c9e9644742d7b4eabb811dc2117a7e3130878639ee021" },
                { "nn-NO", "228c34bbe7dd47d0f4b1d21f34800fce8896e29d96f9de0344dbe418c662d991e904835e4460981b15b2ecc9ea013bcb76ae0ca3d8921158f837c409ad5ddb05" },
                { "oc", "5c243507e07134bebf891e35ecb2f9aa33f7f9f0946b734ebbd7f3137e67f31c9bbaffc5f494342332e441f9f39c94210b7abff9ca3c7f362a34cbacef1b6901" },
                { "pa-IN", "f8eff0ab32df3d3bab7ccd3c1fa7adb4773d7a46aedf6e5de9ce213d5fa04f62ab8b4f29363bd255ca3fc6ce02ac5bc937236db6f8e101b9854cd58b25566607" },
                { "pl", "f201657f1a5678caddee4df8c1a085e17f4b000cf6f005303fb91313fff631e5fb03707c92c93518858f0ffa07c190dc713b64beaef1b999ba8c9c9830781a7c" },
                { "pt-BR", "e2e9fd6d81c99f3c16dda2a60a470b75bfa66f83971b58507af358b9b69f2745adef331531f41d0c4e84c7c773a842195cf114ae811dd18446009043ce2a758a" },
                { "pt-PT", "ce8bf388e87e0c05ed00ade4936c87ba889efb2fb357066d75c2fc7c384d13c70bdd00f95068533183bc713f6dcd3c167782e5e19ef25e1aec16955bab958825" },
                { "rm", "3d60cb7d7c396495e62cb6edc574ce9f3e2a32a6b74a17a2904a4d3d44800fa6ece7b7a013376ed155cb8f65fc030b52e069a3ecb481e95b88b569f267af5406" },
                { "ro", "79bc09bd5f0cfaac08db76477182c256e35b83940312f4c314c304fa14532e1a28c4b285e5252c3f76640a639a15dc51057b3256c696b4768a05e05e15eaa258" },
                { "ru", "5a1b2b91fabf2ada6cc63116a4fab424b6d7bb7edd8a7f3895c0e203365fde5b627cdc5581ef0eea7ecf4118c31f740db3871f6e0aed0e973521ab25bfa75f7f" },
                { "sat", "92aef8263d3bfef46fac3c924d26d9c843fca5e472d68f58f4a304488818ce1b20447dac52f62a504ca53e6459d69c4264fe8c433443d39b2777b89ce092e170" },
                { "sc", "a83e652f6ecd3c41118cd639aaed4a1dd0f625fbc6c08ecd3e9f961528aac629a9a957c1c456009aba74a1191bd0f41779f88d4052b90eecc2f8486b35810079" },
                { "sco", "a494be2c06f6fa788e5d1a7b14d742a433e7e83579a5ca57113ac76ed53b77176c33eedb7336fb4066a58a9431e86d70bfbd38a5e5b5e706b1d4989320685462" },
                { "si", "14af136c1cdeb798e92417b3d57c1bcfa5f644f01b9368099fa99c7db8722a0fc30ff26812ca4187eb9f65a7ed832764a51f7ad5eb1ea6f8698da0fa77d2b59e" },
                { "sk", "091a02ed62b04fb55133f7a19a21c077e80378a9cf9fcdb1ea0e172611b975fb4aaac29c990dba49a26e29bb88129c57b489c40e174e8ec16435fa1a4ab27fe3" },
                { "sl", "40fcdd729369f4787f4e93117a69804a374cd6ad8eb93076cdae58fa344987d39580121817a7dd06fa870c7a57f3c4ecc868bd3ac075e6a30c32212ad49a35af" },
                { "son", "33fc2daee06661380c536b4e706355cc8a5181174ca4121a137aef4b1b1e43287d5d116dd4cc05e531bc654ead71f4271a70c8e5de66c04f9a3677894ffab6b5" },
                { "sq", "cf8c81a915c49e9f5d6a418a94b4047a8822a2f230e91599f5f935dde24139c38c13fdffab8b235ed06812496a632b109dea9c7d9e4e72e493ece2b53c0c5e1d" },
                { "sr", "86e1a05f26245243c6f92b657da75095bf365b71dc15ba25122da78077235474f96a1aba758354c6c445fab5c01682082b07e17679e7930325c37438a9c575ff" },
                { "sv-SE", "f49897f9473ec3f0973cff81712231b9b2453c8dcd0fb60169afbae86bffa6dce853943ae7c5f9586fa1ee2ac75938afab7f43faf4ad5acbbbe4e1af7d1c6885" },
                { "szl", "8fab098831735c82752e9d0244f87fe7dcd53316efb0196c7f89efae6b90976b3c93ee34fcded582000d71d3dcbeb98300622ac1e2d0f34c9108bbe026e5f044" },
                { "ta", "ef12b219249dc31b4480cee96f25e7840178968e9154edeacb63e582428f70dbb7f7715801cc323dcf3c48784d01835d90cd2bd6fc3f18c5a3c3849ddd47f466" },
                { "te", "fd6fbaf535d44b001d949ba0bb15bae43dbcb78add7471411ab91d02880ba0e12eb11fcda03217f4c10e6ded3a2981ec19b7f3755de754651e67e0e193dd72c4" },
                { "tg", "cab71ca5c3692b76ebccf4406c36662b24effcee219412b89af9b149e7fdd2e5f4d9722788a64b9188880a1b420a08a36cdb7c37385dde4321f3b5f5b7315008" },
                { "th", "299ed0d2e58373d7ddbf42043927e6d44112d17547f9bdd1b5a2122895f39b886960e8b968b04216533d3821f6107a42533c622d3d6d0b44462dc8fca4d8ceab" },
                { "tl", "7f06b5b18257bb0bd713fb7347ae71be47007b8361f9834571e25fb76246cd9492633415743ac9d7559067137835d991d8eba636ed50e054c056bae25b45c29c" },
                { "tr", "309e92e79cd5e32b7e4fbdd6e4ce817a9dff9385eea67b16f35a048f5f39902283237b6caa486f12ba60a8952a1b265b5ffaee122a8f5d686deff3a9abb12e69" },
                { "trs", "24ffaf6e23c09ac55e237a9322c19a7ea8eb0e288c2e8991ff955adbad50ebb6f20f086e434f16fa7f15bdcc9dba9877d8277e3e774c8b01a8d8df59e859fe4b" },
                { "uk", "6feae8eb69d511bc519b1753c334484f4a5a864a617ad24ff445f80efd91bce2cba9bf452d39338526536767fef59933d13d8dbf0bbc402166e0ecec053548b8" },
                { "ur", "86d4e489ee57163131eebca3d5db8e15f722e1fdfdf0bf5487591d7622ac086a7ebc99dd8910eddbfa61f6ce6eb0190bc430af007c8b5e185e4507adbc3e5439" },
                { "uz", "e083b9609c2c6cb23b36d33dfeb03561e65a19dbb29d68d145845fd8ab6f8961f3878213dbdb29855a1451fbd6f7c5e96814472cb5bf4dcbdb1ab5f5e1ded5b1" },
                { "vi", "5f2778b41d7db9bb0d6ec477dbb5e945ee98c4d7b1c3d26fa412074ab9d1185d246cea72bbce1aa63d5b83c48bf4452849d96da26b5ffe23f16c18a50ec18452" },
                { "xh", "6c76c23a1cd4c8ec9ce1d5d43dbe268885ebc66693b3e09cdb0e8f7dfa3ec8137ba5fb6204f9e5069da71d206cde61439c003c7361a6f949a80d347278cf6e50" },
                { "zh-CN", "00bf2b1c510c4737c6dcfcde62e8d7070043a8ff3cb82a378dbfdd079b45cadaee835633bd260952a19fd220e079d9c1b8d6da8bf5a9016f88d4bde2afbe4141" },
                { "zh-TW", "7548c0dd86de875dd0701b30805be74f4bc5a23fb82ccfd03ade439bcb3b930f7d925543ba13545af86a5d5fa4c4fbe2a7532d8f31cad9fe862fac8466147035" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/127.0b7/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "8e00e435588343938252d05d5704f03b1b778fd04837d5ac3a0c0cd0584bc131771cfe4f181993afab6f7c595ea9f91c92861637c0aeaef0581087dcac890469" },
                { "af", "bd7ea0f5b272000a97902d4af903264aedda8526f49422f947f85d65074c241404e73ea254a3aa736c68b1d77f8656119b3fb92d30227ad01936599bc5bffe09" },
                { "an", "b37852844675d76ae4be7e63a36c5f902c038f6752ef67c63fc6ccda96d8c0f772f8c5bfd9b69a97015f46e2188f023bd4c12334742a7ea2ccd04f128d12f25f" },
                { "ar", "fa1197bddc5ff9ec5b07822c6c2fa9e11b5565cc8628e3624231f922602a3039d72082a3142066893db7de358ed76f999c60f4db5049620120157c935bb1f276" },
                { "ast", "a687778990471f27c78a6ff5faf09091c7197aba3360379706602ce9936e70ab6a5113bdcf8532e401ff42ecb1c4f98c93872cc24301cbb34020124cf5b6eb26" },
                { "az", "885bb8f80406915bbb28abff01eed13fe4c34e43d6e0599bdb25903d2942a7a306c0163c163ad281801aba55df8fb0513cc61c07d98fe799e1ff974bde1468ff" },
                { "be", "3b1c4dcc58115c87ec3ab49ba7131614bf09942fc66bb983e13e48f1b13b7af345326177d30e31120bccea761b0e8fa66f7fc370bfa9594a5584653b753b28cd" },
                { "bg", "f8ba2f8773a1afa0aec5dbcc58aefa47f5918ddfea1b1326a9ec94e409a021d560ecc608589ce1f20bcf32b03b55a583bcec309470ab8bab62113a3882b1d41a" },
                { "bn", "5466fea6da264d1f8f223f00c6d06dffcc1a97c1739fcb9eb1f6815df8f51eb011e7bef9fa7d91e2a33a281c682c83f50665721036a42e8759a23e28280d77db" },
                { "br", "9a23c4c523e5278d528179b4d5aa9de74371ef6a8127d8479990fb8fe5c2d2c072665be5323101a3f10afef51202c0b41ecee84c76efc4cee7f4bcb7bc7d81ea" },
                { "bs", "9a9bcb00ac8ca099574fe88e8867267253d6bc09db2c5027d6396a09135f381f1c4abde5aff281aa2c49ed7567e66841cccdc5988e800cf037c70f721d1ed0b1" },
                { "ca", "54aa3e88bd0e910fd04d0cdf9812e4a5dce588e76a19d749209e8c9fc323b50c374dfb386bb12b60ad03c97aa2851dc22c11b1f827250f28333a411d5ab78fe8" },
                { "cak", "718630b54fad7acec02d1a4c1037fff887218a3378db66359dd023793a0b7ba2d3fede1f8f072f1d6c1045ab12f59299bff9c0fa94877d5b9c90c82e5d881715" },
                { "cs", "ef10a47f7510c49b3a61913d8f209ba3b610c5d3d132226dec7d64440cabd01f8711a965e7b1aa7868e2bc464f08b4768f8ca057f4827109ee147e5d759b698a" },
                { "cy", "c46d6cd126cd2e37755648c24012923ad294b3c3362f0f11d505b51d782542568016b0456d5e821ee9e39ddaf4a7221c361ec11b61e9ecd4b2f1d8ae0a74d267" },
                { "da", "55cfe66683d4d9b9a995d13fc4282f185b749eb1d2e14dce0b47e57fb7380cf4aecdbbdc84c667e82249ff106024a7c68e936718c06ac0a8cebdebf7b709daaa" },
                { "de", "1358b5a4e16936235994c203e7a6e46a0c9c6832277958dfbc128ffe59a5ae277d61985bf6a6d8b9abe08f65192f4ac6888f82826aa4bb96eb27d39497a30ac9" },
                { "dsb", "afe693240c4070361863ca4e8592b24018ecb3de9edc22f2bad4a3b63732e83483dd67a0db429ba64033aef4580f36399b4bf6f82587c7d68e416056c6c541cd" },
                { "el", "7cd2ec93ff499b99f5bfbea76b2a28bf9f843d08fa3618f4f817649cf3510fa2328f8d15dc3a17b670b2c1d85512fa8d3337b8b1a4d06e548c5350c7365c5cdf" },
                { "en-CA", "88b70f2f7e26192f1ab9cc40b980f84097009e43b9c18e4e240611270e4eedd9a39685781f213c9d4147fffae1f9bfe15655b17f52a2236e2a0950af7a774878" },
                { "en-GB", "ecba948378e9027dedaac9bb93f9f5133027f1d9ef3897ad690de430bb5a4e2d4c6c99d834686de1c67ace5915b4b37a71e20456c678a2959e2bf7adab9c800f" },
                { "en-US", "fadb007c7bd5b3a73bdebfda52ab2ebaf4c089b2408270edc2cd22a036e9304b52bad2ffbf6f6307797f445188b1899b80e724ed5110d815c299f60ff68b2c60" },
                { "eo", "8cf9aa56fe895a3c4af493dd7b2e8fb1b34546f043faf49d7fb3d8f4233a5664e30690e8757ed2f30f479ac06921cb2f96e23d60643b5c443faa1b67cfa9b70b" },
                { "es-AR", "0481d8456eec7d4c4f5776313335568fca54702ffc3e90603f02db5b163aa503036017df652d466423ad4bc71951f8851e3098668c3447b7a023aa6f1c952c4d" },
                { "es-CL", "9b15707d7da509a9e124b2258c9b49881460e227f60029097cc1ed053693dccd4d7bad1cf23b0b6bd4e2064f065ee640c7733122faf7b3f587814dee4dc3a7b5" },
                { "es-ES", "de8c1b4b3265db07b9010e47942d9167f3a23eac243079ceec61757b7fb71a107b55f13f9605dd4411cdd0ceef23c8e47414f84f478d81fbf22f202314a6e590" },
                { "es-MX", "e4d4c994c4a85237bbb88f2e3420bee4a4efc35d3e5f4f77c10fa5c55a5bf276ed692ccab2c21e549dcb8d4adedc24c584b729d935332729f301957db06a8a57" },
                { "et", "00704baa6e855da90493ce3f4e56f09165b288bf046d83ec616475e9a7cf83bbf71bfc0aebc2d979506613991e2d292d3ce530b676aa6e95e3bcb0b1b38a4970" },
                { "eu", "4b0386481b8f609f218a733d198750f0e199adebbd05b4fafdf885f5c663bc77854eae349e6b5d0b2886b85cde5322037ae9f7fcf591902cff8c32d292554cbf" },
                { "fa", "539145f37d10463da5e94a8856d26ab3d6c401ffc36bebc3c4b888bec0d2db4f4ef95a799141a3271a2bf85f2645958371c492e37282af48642aa0dd3a63b33e" },
                { "ff", "06f625fd038bb876f8308bc581b641a815b24cf9d3923515172d4fd3e7ddca1220d43d52400ac1b714067ca6f045e10606c565d1fc2f4509b50651f5dc24464f" },
                { "fi", "8827a7904e8957895b8b2ee7102df787847f8a5a09e218ca7643247004a504f0eaa9b7c45f00a48da96cc095a327876ba2f63eaa1f4866b1175a4b72d7ab1798" },
                { "fr", "8bd549b84668f0e486ccb81f5eb3c322efccde4f935b2d19a1fac04d27ee576c6b2deb8513c75e8bd126d04e703b1a27ea200d7ce4b066e04eed1ae10b81f696" },
                { "fur", "2b032224c51bef12a4d7f7d1585fdd240d7207c8e060461466209922dfa9238735f47f061a16ff3db2664d44cc196d3c0451209019f9fb46fced8ec1eabeed00" },
                { "fy-NL", "c8d118b72b50233b2f2382a4f12bbada16510cddc75c237cbf4a60a8bc3355b6590dd8b912c5001f57c7d9d1fe311b6a68762313cfd5cd0347591bdf93b72e4b" },
                { "ga-IE", "927e035890c82bd4dd90b5b62594ebe29d1d3f8fea25166ef9914068e1dd66afc8a7363f46e98988ad0b5a200ebadd7a4035f86434fa7cb35413c8081e42d062" },
                { "gd", "31a97342f4de5e0e90a57fcd00385f033c236d4487f3df68ccc0755d5b8e89926f3e3b846b6ad37c56db694e1cef847987e977f457a52091d4da03d931eb49c8" },
                { "gl", "4fcdcf7bcb42fb0f20bb3184993f008d1a167d7ee54f06c5040c0d306b27abc5ba8fbe842e72c95f23882af51c27e2cd28e68fec7b9aae2097482c203cd5541f" },
                { "gn", "f97ac2762449f6400f41c2cbaf53246edd5c88b074d79e03a681293961de16bb70fd51c56fc5cbe709aeb51a8da61d8081c9ebe462c45424f242584cde2d2deb" },
                { "gu-IN", "d9e243b494225bfe920e5695a1faddfad494e948ae14af1e918ed6bf2a6aa4fde3e23442378b5d3602344959869325040061e449b547d436b6ed9629e6898572" },
                { "he", "c83e20a935fd0c848705e19f5a1a23edc7f762a27dd98efa6ed4125f872ca2dd771597fb2bb44b016b325c1feff0b9548aedb7a346ca9e9ba5771d2be525c53b" },
                { "hi-IN", "50112a959cc8225e6225481208ec53d17cf9e25e8427873ebe54d79ccf93c9559675fc45bc55b649d59af67fdddc2c5c51dd2d08a5241a2da8cfcff19355a4cd" },
                { "hr", "26359e3cbcf43e7de433b96c53f2ffab65a84c0fb15aa9aa203c00995b9fb05fcf7543793ca7e5a77c331e2d830deca059f97965cea66ece174119e225b6abbe" },
                { "hsb", "d2a0ddc6edf5fe9972d0f51e6e1d7d00009428d4940bc50bef2a19aa51d84b0009d0feddf0116660478abe067acc47b2cc0c8a159037a7c4acd44867f409f29e" },
                { "hu", "08c3743327154550c18330cdc30b790afdedb87bff8e288a1ca64a3e259059b8b0e19ebe2a72854086d84f2bc20e3d2d46ca47f2175034af2d0da39f85d1061b" },
                { "hy-AM", "d40865c725ba159e6abaf003d228b73ba6ab40e798e41a355baa3a743eeddfb74ec625068f67fbef13fe314e50dae33a98e62abef2169a36cbd5be63f9c455a3" },
                { "ia", "9bbb058f9b231c9837cc7b1cb78c35e93cd017ff46365ea842c23909c5a6dcfcd0e39d2558cf8dec23719fd3b2eb4888c106981052c8cd4bb25439dc88e67485" },
                { "id", "475f0a2f0f1f49ffe03868300b92e2e3d66db04d82eb48336c8f58e1bdc655f914cf10cdcba18faf349fd95c951e40d84275bad86252ae426020fa90b91cc0b8" },
                { "is", "5a197765af3ff497e5d4c764c3ef036deb73db4841b38d09c3de9e4c02db87f10b19c65894c7e18261a28fd20ca005fbd54df3571d8b9bed20c146e884e4d39a" },
                { "it", "adc3c9fc0eb95c451f251b6c9a99118a5ae215737b608a207493ba0006f08e4f9bbc23aa3089c465e3105999742f82641a2ed369d1173ca98c76305285b4b5f8" },
                { "ja", "31e877165caab49401585b1062d134b4371cd0d9aff9a0a1f82997fa5145875954cc7b4e7b7645ba7b20eeaa25268ebc4fbdafb4351953ead475be84e147a7e7" },
                { "ka", "810b66b81690e02e922fb0dae4f3f078e8aa30cd11284018aee9f6bf2cc2b0e627a018e25f96512169075b1e504b4cbcff956771c355b2ffe1a6c5ebb8ba81ba" },
                { "kab", "50bb8869daeba87a89cf40499fccb3baceaad4aa6787bdbf3cb62a25c06e672e5a206eb47f7fa5151e863206ada24bdeff7aa747914d55d7f29dc122cf4187ce" },
                { "kk", "01f87dc75987192d9de36c0fcbdcdbcdcace1e7a9d68309a557e9fd9b3da38d4c0fca1ce167fc90042217c45df92ab1208a07139dbf68afd4b1d4142291a624e" },
                { "km", "7813fe69dc83e7ff4dcb20aa4d678959cbe69fb4d6f7e4ee2771b16a3eff2677346f03219a02f075ff23322d2f9234d2fca0d3fa7494d321ccf13e395d656d77" },
                { "kn", "46ace3734e7a209b613a64b7c9e9a18a6f78c7dbf556212fe9060637127fca4589bbafe8e457819950b96a7a8382839e5e6bf60e3a128cb4ecfa37c5d59bcf05" },
                { "ko", "3daaffe98390bc61615987a0ea2a5a199a2ad7aea1e46808c08aa748bd503a7299668b5291286bddd001b9a6c3e985fd8a772be290c2fdc085fe80708b145f1b" },
                { "lij", "c99771acec9935eca35c9db89c75a1cb726a95d9c944a68978f307d153c43606479a85813a0d07c9439a9b87d83780494544f71f2ff4434c680c41c10bd51bff" },
                { "lt", "12bb1c0ee1c2647d15212496eec2cdcedbfe9699d3b1fc51bc3f613533a06b13f18fddffd00030c2fe49dd9dc7f204b5679646d8d8e6bdf93494439e959998c1" },
                { "lv", "f40abc3eaa86b196dcf7b965ac63b6f227a05b2b3f3b64f567a551ac7bd3de06f5cae282e0611839c030cad8fb02b3233cec6f6a76f5243ce3aad87d1e146461" },
                { "mk", "c993f2c13052d0311a1130a632b0b9cf82aa66845c83114e01bfe1c770ae77b8213a31479eb73c31ab187afd14fe6397c6a520d76391ea8ecf8916eece7ef903" },
                { "mr", "1f8229961743dd3f93dc2d45c47d471b718b2c17f4ac6a5c7bc096d6a76b9105ccfdede3dad90da537c1fdb07aef8e0141691139651534a99ae0ee517233f18b" },
                { "ms", "c69da040e64650a8a27ec071fb9c77c176cafe346110bcdf4b0bc9e4039d6ec97ffecbb440e1d05e5ea4227bea04939f4123c7f634f4ea08539ac2c641d97453" },
                { "my", "3f09b31a078dd401953d2b472c650e35107a0af208735fe9e9245501204a31e834f5d85e78facc91fc847e52e4d120df5f4787885bc851358d914f2346081f24" },
                { "nb-NO", "678086aac5b5bdabda098e46cfb819e895b46f5e4a45d40d1fd26e35f0879df322997c82607c762e8508cc3a8f10d10e83ae7717b0b9af879af694effddb408d" },
                { "ne-NP", "35040d90ce1649c852dc6a6aea7dadc0912418ebcafa3a6baf6cd79454b85665264d4bce73182ea174c15885b67df834f25298203f137c400bf8f2a35675184b" },
                { "nl", "b25690f58e1910cd804086fef9a77b8a5c0a61f109e0b3f63b6ca3ce2a65f17861c0eefd46f07f5d53845938eef79c3f1f33dbb2dacb3c0d6d60a67dbeb9c35b" },
                { "nn-NO", "06a3dcdffb5224f835a2968e45749e160105f5280ac75fcf61d4d83bdfc1795a50c0fd6c7595bd4fc3a81acfdb154e5de95c551683b070dd2df6c41ea14d4e93" },
                { "oc", "20ddb53792a2cb6621893aee6aec41479345a7f4fc270845a96bfee476086d29101b151951beedf3f023fbf3a8754cdea1270e64d60162222ca3d0116e7df34d" },
                { "pa-IN", "e285c5ba7a5b149ee449505731d7485022aac12058006fb436502ac3c83eb6c9aaee8889847a9167d34f3a140362e35b556b2aa15da07535510d9e28eb45e189" },
                { "pl", "ccfecba0a6467b21702661d84bfd17889b43847cc8e72cab16c5c0c6ceeba17e32e454cdc16227d39db180f7647fd303851a3dceddfbe5990cb3cf2f37d34ae9" },
                { "pt-BR", "834f73dda7599b1600f5a4905428f4b979076dc459ee889435ca08476cc7f61d0472bdea1c16148143962d418c664aabaf5acc0c73d56a04506f646560116ec6" },
                { "pt-PT", "b2991c304b70dcafd47a481f7084d3e074f0189c6fd95192702dae576c778d085d303990d2f124390b0856250be1451420f04b5b8f662c0f2f1627523ed6a033" },
                { "rm", "9012709b4a048e107ef4b96e8cabe9d9ea3ecd864aa78003b7d53acb691d9a505fe6db772f29a5c7d0e780439d0bfa7a07dcf799b2106bac25b43eb921ec0e24" },
                { "ro", "7ce056f9557bbb2d0ea435bb2dc97d20dd71c6e8d8ab75924a32af7996152c79f39d2160c9c534a5b931d987f4229dba0e64df14dc44930b317b5d19718972e4" },
                { "ru", "0bad61c0c0d8039326b3c4eab5943c8e2a330ea96e93fe306578f871ee1830290dadd4fe83c48a5270f5a01972222836e975c8c2963ce5df2522b56170627e1d" },
                { "sat", "60a376b3216b1748954a278385e601421d08c49a35cf54c918db0be7c04eb438f20ad3494e9db2bf5c62ebcbb3962751a9478c17c5f1b09a54f57f53f27e9ae5" },
                { "sc", "2b1e110a0dd08e17bf61323455671349861542d8602325b5e88a88cd987318eabacddf981394aa42957db2abb5768c4841bf8b805b5a618d283b8a22021ff05a" },
                { "sco", "37a66d0c487ce1178395622642280ca186078a12dbb026fdce6ca0a91c05d5945b6a087fd095e63289e9ddfd617c24fa7c3829d4fdf543c2f15a299c99cb5f80" },
                { "si", "f7303b0a65ce4e76152a8c2b551bacd802064eb52b4d0f2491540d4d6cf1f8f1855da9d1d3a4f4bb98f89fff2ce5819b506284a824cc7095b26199015af78719" },
                { "sk", "e033f8c49478230ca203b8c307ca490c33852c601c652506cd9a8fd49d6a95f1b5f05128541b7ecf624eb3e6ce08c4ceb1394f1782d8296ea48fbaa2c69654f8" },
                { "sl", "362d118a0f442f2df67f18fd40d5601a008c825ca776267618e0acd4df80d93b08ec652767116ecb808cec8dfd0e0a7620bc7a6483f3ceb805a4bb40e0934120" },
                { "son", "bbc7dd1c4a7145d1197c68a3e801fac4923a1d3cbbb1082832d0d9dc8e6a1212002bba10ed4138ad034a99af5c79c9cd2e26c8953b8039736fe6c77dea05aca6" },
                { "sq", "a23132b4713e4199198e8c8dd114d214ef97839426272b7079bc19b3d3abf99d296391b649e394a84d5a50854cf715da4212dc073e16d7538e8b9a7d3d98b864" },
                { "sr", "f9c28803ed59e7301b54be33fa8ba02feb92f1fc5f81bc0094be51d144dbef00d79c29fd21000e29785158e583a6c12f48cc0d694ea7e720a0f77743c9735aac" },
                { "sv-SE", "868b0064ea99c111392cca09b695e1e01d9cad903159819566ef72b60dae7483ceb7f048ae8af6f4cad084a1287390dce47a5a84c6d23875779e5fa329787b97" },
                { "szl", "5fe1bb97f518c75fdd2ee89c3ee284d5c8bb8e9c48578308fdc059e964f4b11c337ab7c7d512df662962aae572fa7effda5d31d505a3daeaca2dead25457eeda" },
                { "ta", "3cefd6a95871619567e13c2c1a0eb199d763e20839603e6a1e24784d70651c806f7dc2cd45eed7293a92f84b226c4a8e0dc70efe0e3577db2bbe0300850fd7bf" },
                { "te", "23ba2a3153a7c5ebe31e9aad6b3d6a76b7a6a962732c1655100ad187c3e24b64d14defbc21bc5a43c3e4b27fff86a735b85ad50de26bf2476feddb15fcbc038b" },
                { "tg", "595f945b49d55f9d3f406e9a3a7d8939c78938c3a2a37d2c0077a3f325673e335e585b3839837766af4fa23ea32b0da338789bb06008470bd28c252dccc58b57" },
                { "th", "1c54270f55585616381575890bbfa6e983d5c2627e50a964a5d9d9dd65bceb3e23bb8b54b76ded2b93e667d29a60a9937906d34594eee72fe3c00bd572b928fb" },
                { "tl", "222ca380143f3c0c6e918a5e602f314c3a1f92ed64c591461cc3563a1c7ae827b9edc7608983939d64cc497c84eb08b73e67b206e020779e6407e1bf052f0f57" },
                { "tr", "2d60e55030e2f63a070fe808744bfc385ab9bb498be2626a89a88f311a326a6055fce7362d3c36204bca56a6bb1e4ee6a678a63276811f7ac73edff8d4be4e39" },
                { "trs", "59c1dd04346eb518f6dc7bfa46333297deda335405878e23fa8d5b9d87a9dad0b30a95840990184dd505aa9c1d0a676817169910711dffdda281c05b8b9cde20" },
                { "uk", "e74d094ceeb269253ad11d595454872d5f1e6aa9799570c2a1b6f69fcf65fc8fcef2f6a834cdfda3a0218dd486b2e57d5c912141ee6e1198259b081cda371a77" },
                { "ur", "7cb3b7790ea739758a1370d223d3c7e52c472f69627fb07e945dc250d1eb116f199568fe36c95222b84749abbbc7187fb6e20898f72ad22d58d76421680a3d73" },
                { "uz", "10caa970fe02be708096879a09a5b13f912abf00f7cadd10a919103ed2f4928b57271872776849f0fb8b62cd800c25db96b056827fb502e4c22ed344ac065867" },
                { "vi", "f7b5f7e2d8572aea1607551b8bc72be536aa8ad5f133a0600484a771df5576b432576e1194d52e67862038657a44350ae0e709eac8e02940501d2dbbab2d71f5" },
                { "xh", "198b4a9e672ecbf706d420dafe41b53f7734447ec03930e44a2a25e535c752f5a0a7ba6edd3cc49a4a45bccc47d560eda541c7b0a0a094ad8c59c0092d665443" },
                { "zh-CN", "52dbf2abef5e601277fbe5858416e5b194a52973d2a23b6284b0422bfa634c6e6e3e33b3be97eb5c8102fac5389f9e6602cf9db16065ab0d365b583f6d1af6e6" },
                { "zh-TW", "0118d0dfc0514cb78852f74f9ec59561287be3b6e0ad557890aa3119635f16f72b510aa578df847636b877879a62a95d9235f649e0eace54d8f536eb36d5781e" }
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
