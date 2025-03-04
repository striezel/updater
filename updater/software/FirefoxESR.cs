/*
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
        private const string knownVersion = "128.8.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/128.8.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "de4c8735c83d292032b30abf2b212b15ee1116088eaf7f7a5064084a4554e47e35e27de2f6cf013c6bdae6d089192d3c0f1367ccd47282639ae44a706abfc732" },
                { "af", "f5d290460731fffe833dcbd5098902c583518d0ce3e2cf683c2e4af4ded6a2937912369f24b1bee07bb4ccf542da1462f1015f6b00ac89cd772f003a4b682fc4" },
                { "an", "3e406855a1950f6e4f59f4b73102d4fdcface927969f338e96e03f4f02a54fdf37b2835e79bc81c8a6d0ac61043c2e29cbc314ad273dea97fa2d12ee68b7953f" },
                { "ar", "92bfb5b76e446e575ad945abcda8c46c4ade79bd277af50556a614a01d1a2f65bd0e6e9fb713d1ea591ff2ef0789109549900873fa5a7a19b259524422692d34" },
                { "ast", "f4e2920c96a02946befac1ac8906742622a78d752c5b6ecc89727ea7d9ca553eaa06eed8f5d4c9349ff9029b813bb4a88ecfd7844a964848d437300b29290793" },
                { "az", "7dcc6feca81b3969d0b8af9ee87b766b53a3a842076ebd660a2dedfc072fb2b9696f0c0bb8c2023a3c6d78f9b5080d9bca2f591e6091bc0facfc21181973c74a" },
                { "be", "35400d30b0c054cec46769f3684794fd4322b4b1edde625a5b5df0017ed5b2ca39206d6e49f2c56da5a8cd912cf57a37c37543920295c50592f084089ba0b372" },
                { "bg", "7c9dc356e45e8dfb18bc630d1a4dfa6370d9a72260ff968ff7b820cbc31f1311c2b51c4e7bb5fc50897d68751d7a747a3289a8582585e942bfe6d8d930353402" },
                { "bn", "31a9eed6da4ec8e010473528c63f5dffc040a5889637b7c341015cd81b0affa1e943a7a329bcd4dd53ae1a0cf13de242a47a031285a5eb021a5b790dd5051477" },
                { "br", "df5a69fb96b0d04f70f162ea804b6b0330f5f934f75ff396134052616d2d71e66903660d14123d4c477d3307850dc1e00dff55374b822ac3a49a63552b1d78b7" },
                { "bs", "5522e371b509f5b5bd728eaf179de9ec8335c1f4226884fa0fd0a97029d3e777400c26a6019e5f64936018ca60582a0f2fb8c38afb939ff55bad1f0015bc7e4a" },
                { "ca", "a4686986c73d12eab82b937ed865d34d3cc6ce4be2f6c2622b4d65f2342e8aae026bc9b0f982484dba57471057cd8a761b1607f9c61231e50fd580ffc0bc8898" },
                { "cak", "93b5267756fe2a8894b2b93759aef3f09647fdbaccf15a4ccbc380690eb68a20b5a5d30fd9d47b68162ba6cd53b33cf3a06efc9846de52f94a5fd81e61df66db" },
                { "cs", "90308b95cab94e0bfcccf5e40ed0a9f1f58fe12dbf53e2f8c270d88fd8cfea43c4263baf7c8284c49197c650a668557e5913c552dfe913b0e516b160b8dd86a3" },
                { "cy", "07144f35ae1334e8585ac2cf3c4f7d719ae91c3640019bc32055f5848d5717ed6c47a106e9dd743bb56e80f211c2dd4af9a7622d43f894f203ddf22484681b80" },
                { "da", "74ae69777710ead07d6c4170f07abf42f39e4fd9bf49c8167590b6fd3a69e920888454393fc6d70bbdca999d59460a07d37f7a4b29fd155d05e8ebc98235d3f7" },
                { "de", "616a8cfd1ea7828f41d8f06ab451784f84b3edf566fb10246aad7cf9064effa7413dec8b4bd14d9c23d1445b10fb63070de6ca09764c01c7962b67a50d63e29f" },
                { "dsb", "c6e0fe779d87b5863cf4ce5b903769d080fb39631256c6ce0b47a77911f9854fc44e8c8afdd6de2bb69b366b9bec2a833ad1cb73ed6126f8a9afe9a8c8f16b24" },
                { "el", "ff06f3094a09df1480962005320d2263b14e2531969869a08f8960dcd13d2d28a52c1d60217830b865ea8581fba5256f0385815b79bf7bef34e088f7cfd006f9" },
                { "en-CA", "9826452d122330c169579384074637d715ce0b0b0333eecb8a665ad98222ebe00aacb512890f384ae3efced5b48dcff401dfaccf942ed65c93adbab4019034c7" },
                { "en-GB", "b71c453552d276be9fe24c225909799af8fe30c2d83981c4334b58a9bded18225e57f4946017dd7c25c6dee664ba4aa6e8072a57e962c706c932dc4d0ed60f9f" },
                { "en-US", "7489bca5a20d64835a4251df3657b57162fd59d3380b849bb9f9cb65bdf9636ea95f47d2be71edbf8708aa0cb79d9c5f0a9f9a459c2d1e8cc84f80a99b3ff311" },
                { "eo", "fb92482999f42dc68bca652283d425e33cc664ecdedcd5bed5b9005f4145861cafa1613e280fbd6db270c8a5a4a80522ba3c172067a155841116161f7888d89c" },
                { "es-AR", "072c55febf4a43ede47dafed3436b7811f5e3e2d3fd6ba3ff81a72db1d35f67af3a684f024c2f871af3cc19e6f9c59bd7d1ee4fac15e6b06daa7e20d16c558e6" },
                { "es-CL", "86a11bbb43f27b4358383ca2f9beafa7e0bc2e2281504d749c9a19902bc08f7e9e514a805a4fe53c0af17dbc9867b92e2fcf951dcc72efb209600437f8b0a4c2" },
                { "es-ES", "446a63e34480ccaa6cf2960247ae49dba1ba5274970a40f0cb65441861d3d9d6edcefbf979eb79b2ec95b83de1ae2d1083e29424f2d67c3a40e349dadfd7890e" },
                { "es-MX", "87fe584b8016fb1834ba2aa5612b5ce24ccf1068121f081e3471dc6154efdec7a00468980afc8973ffa226439a07bb8cc69aa82b99c60790c65a8372319fd016" },
                { "et", "d608bb4fd12a8d3b9129f92265f4cad1b42c35fb9561bdb2ea4e02d44c3edd588a07236c912849432f3dd21dc529e6677b9e954354a5e6dab79af8da0f56775c" },
                { "eu", "006e75eed3868fd78a43b9e5a85e4957f8df264114a2f0af7e5c8917edf19d399759cebed56b3eef3dba35fd1b3ae656e82b19346683b8809779974a6d8d1c10" },
                { "fa", "85a0bbb05a9609e0ba62b8631f941e459784ca7638a9aefc22e2bebc488a6156fe6a43988b7ce17e5dd6863b2668f927e789396fd27a35d54620931b6605f277" },
                { "ff", "422dd74409844acb087ac22897769614bf4c30e1505c655333c17ed23316589d94a1df6aff81f36d90355f6b5ac56b4016dd4cf1efebbd43070265ffd73caf25" },
                { "fi", "bb773568762afd1c3c50670f300e3da1d7ce658221693817a70ad25fdd15042ff47947fb21fb865bfcebc36978939aaf1b095c1c0a644a274b31f6c6b40aefc6" },
                { "fr", "a234c36d682cc6dd4d6c14191967d70e1eca5f507a04b3111eb6d45302713261154ade3e7aba8943ca420ccaf933051eba875aceb8c6d7dce23bfc66d4fc7ac4" },
                { "fur", "765145f71402de842424568678c014ed30dd02ac5e245650fd1e97666b54d6e53385295446ca1d034a008c7e9c98af982364fe76e5f912464ea31dc672180224" },
                { "fy-NL", "28b206ee8cbba697524e50a9cdc776d7fea7cf58560712cf78439b0c525980676ed51e509ca6f53b02466503dd9ece3eb52e89bf75892de745b257a718794a7d" },
                { "ga-IE", "dbd15db09ce49b441c5ee3bfff2cd2855d04d1a33364c6767918a1a2b8f48c75fb5a02eecbd17cca73885125f4d815fb09bc32450259b5a2a1c68a8cd5120418" },
                { "gd", "6b94772ff78ffb9272db7e8347cbecb57fdf053bd57d92e5d8898a118333a998132298236953fae05a827d87b4ce4789400ca062b0c96784f6a34381306e6e5e" },
                { "gl", "454c9bb74ea344775babff7d4f3e5140389067f915437c97c2b5d9f363c81498b6e9bfb6d4dcba53caf5d25ded2193069a5bf03109b885a74bd34adf121d577d" },
                { "gn", "e01c694cdb104f5ab6fb09951cbea38355c26e1a0106608fce3ab1ba3a6db6519b0e448dee9eb5cb692552746dffb98093891995331efd3b934af1a34db7bbef" },
                { "gu-IN", "f1dff4cfd3132c88226d16f1ffbd76c462c7b9df3676eb48a24baa67143cfc9590dc8fa3bde1f9b5b4a7aaace1328edf544974971ea07eda1a0260e23b46396e" },
                { "he", "32d27da6ce0db2541501b7fdad845d0cf46d4a613480b9a9da186deec34a8d4868204762205694b1883a0faff9f588901e109c76bdc6aa6af8af28125416c770" },
                { "hi-IN", "0e745884d5d5aa24384272d478fca5e570ff2f39f5d709ca693b12ba5004c7c1ad9f801469ae419385da98f9efb8947c280f387718f9b53e6dba886429be8dd8" },
                { "hr", "58d67c5e62c7f2616dc734e83317753a4c40ab86fc86311dae197bfdb08247650f12c18e1b6c6e1b41a3e62f7bc8770c9599472a2c681c659d0bab2c0e785b35" },
                { "hsb", "4af84981f28945e125fd6703ad593234e73e7fdbfb18c05b3d12846dcea8b40e26953774650f916f02ab31f2e23f3b02c946bdd32e865bd02fed0363811e56c5" },
                { "hu", "8a6fa0e794886dbb94cff5e3a3f13fe4b418df69a4c56d1b6b77ae4834e20231344db8b7042dde26c7b6573193e6336bb252a09c01b258f4c169933061cb6505" },
                { "hy-AM", "ffcf3b326e39e1c11b183698aca8a64b86e4b5cecaf4db8332da00c54b3908eacb7ddcbbb61ea027e02d3c99b88d3caa0794d707190120dce72581fefb0b3fd0" },
                { "ia", "0fceda27bf8d23f9bf06425bc1fbed5ddb4f9a53582a661049a8e5d12b43585750007527a61a8a31f6eeef18206d2fa77d976a2ce099ec2dab8ce8ddfcdf260d" },
                { "id", "55e2ce7e9c0a69bb8e5ec7073b3bb6553ba1321737532850495866fd5fa4a1a6bc8d935a472c41780d8290d7d34123a672b084feed1a16060dcfddca46e87e99" },
                { "is", "4b2c14e4ef437b1e8ac045a848a8a5a6ce4a8bcd2fceda7f70ff723d4687c6416e8381ae39b168c022c6bf6df976a78ef218e90cd55b80c506d2c0438601e566" },
                { "it", "fdb20cec81faf925506532d4bc8f1eac2bc8424c428295f2e31d5b2d038a498c5e8d9465e21a0afcdac36910e6b5e9c832aa4520773e8a383540de03d255e2f3" },
                { "ja", "d9e36dcbb1692e1d624995a92e088e3c90cb32ea2f5992c9ba3ffe8ea02a328a363ed8fa448a7a635a94feaec3ae7067fbd9ace643150b59228bf4d67e367a71" },
                { "ka", "b9b82d6e2e025f1eb08431b6758082f3430e97698f2a2a147630acfd4f4421890b2e4d8ce76ab5b38be65d2ae5dcf5e4d6e3ed2f846d8c90c9621efd5edcc932" },
                { "kab", "68b83dc8c0afbfc28b8ac66a13453e209421a2b1284b5c57cea256c7fdae111e8c024814d638ac2732c4d0c507a146e0b400687a46890e9ec50cca6fec95065f" },
                { "kk", "6a4fcaece76f7a5718ea957a8d2f91d4da37495695ff64d9da3911fb175c2374bd8de96c69ee8fb0afb75348179c24c3550d9a9f20c7bdd74b5fa3aef543a972" },
                { "km", "29b2f82dd61283cde4436dfb93878091c054285606baddad5c6b546eee2441ae0690ed5209c319dff660705b48aba547bf60851eff711dcde057dcfa177d2ac0" },
                { "kn", "8758bba853ebb42cbabe92f2efd71ad49f8631305f68a8f214d790d65d96b1ed00e713300b0ced667e9cc5d9959fea5363cb37088c3e1fafe5c26ce9f883abf7" },
                { "ko", "90347666a0121f293f48bb7047662c87e4c8eb0fc5bfedb8be469add5fa7f0ab2cfb471d48b1cf487fa5130e87126e5c8624f99b625e92de88f8968297a20b39" },
                { "lij", "1fc9e2bd84201d7dc3b7e534d050bafade86a1de08cdd40f7efd139598b664a1eccead03d7553698e4b5225a1fa28ef89e82b610becd12f049d2349b88f0e4f2" },
                { "lt", "37ce53d956e97117b14f42808b6faecf9f34a2fed9e63e61c21eb1f9d4b146eaee95e574394bf1134f4a2f3487c32189569017e1f6610c3aed388c28da42b5a7" },
                { "lv", "c69952aff5f3044bb2bd741a139a1c18ebef58b28dd11e6bf3cfb63f3751654823025c2c55e38213d3c98faa16ad568b514f142f41913ed97723abbea49ed282" },
                { "mk", "79c2a543e7c048ceed1df310cae62136cf40da037259f10cdc669400e7ef9f37bf0066f30739159c46030933960d520011bd8f7d1789db0506842ccf727c129a" },
                { "mr", "f9da01082986d59b2784aaada6d300bae95ef6b248ea23ffba4b489cc7382860ede4a403e2e46e96c9be42faf9084a3c714c0e1fc1c006a38364d56906322062" },
                { "ms", "374bc1da9b759f0641cc0b18923846673d719916f2417b9b8f0fcee4f7e733c0d3b175f0bac0833a9f8c3d067e8433f9686634a9526e6118dc482d435e5631d7" },
                { "my", "0a9082ebcda919a7937f1d7cc1fffd8031544962634c31dbc846bd461ddf79024469b1a6dc5aa2ef92eb10ddc3d291552577e7f6695099565e7de3765e9af9fb" },
                { "nb-NO", "263c769782420d44b1f1df23870525f7d20f90b104c17431d7e2a689ca7e8f864bd5a2af63eea4dde4f541db5b28fd0a6fb8850fc0bc511884383ca1142d7e49" },
                { "ne-NP", "6f4386f6b21b81f690f2dca72d17ec86b375903739649e22efd7d2a4e93f87dae76e1bb1ca742277fcd1fa05f24197c5c9e55b6a648780bf2942538ec43b9ee1" },
                { "nl", "8462a25c180306686d3431016e8e0e7cd2fc53bdee87ea34f9eeacc7310aa1b14b1b1750eb145e630054d3fe79e26c468ee08b710162d9a66897dbf51db60ae2" },
                { "nn-NO", "796a66f3da63a72bb6cdeeab787de46a2f4b1a4797b9fa91825006a8be5f9a2b32c10e7d90d8355b7c33a9740c2f356fffcb488dddf0d5e4febffbfaa7ab0a46" },
                { "oc", "3b8dc8fdd6e9f3cab2d070ba2b51a9f5457f231271a3fccdb1965f027f58a7acd48a057f1e92156d7576995ab9076daf438b2a030e179d49e69cd34df57b14cb" },
                { "pa-IN", "c96f37cd50e886a0600301c34c15c34bb232c15e9da88033b09ff1577d41e7fac277fff074fbfd1fb5954a66f59b39077f9836783e15ddc50aa9bc394e5f83f5" },
                { "pl", "262fb6003d61595e833776618faa8ecf3c284b854062e0b24e1492f5518f65cb8c79df4d3f507a09a0b12f4b782b4fdea0e45ed90bfd84f2404d0c82302ae7ee" },
                { "pt-BR", "b2ab46c242b434859b47cc60c641ef7853e19ba6a41e10582c493c6b923ba4c48626554d0667a397028d48841e235e85a84d18efdccc929f84baf5818c2aa63b" },
                { "pt-PT", "a5eeaaab0c8878af1c4249d19e14ee4013a24b77ca6489ca8e7c9b74cbfcdcb1267f07d8f3119b84e9e8655f035c59fb80a6f32a2264d638c8bdf6ec0630107e" },
                { "rm", "8a05e680d13d0262e9f3f58b96696ed701c861af80c7171c3df036247cd1106f8a077efa92ba57191237b4924f00ad157db055e15d32889f0e65ac59c7ae90c9" },
                { "ro", "e3fd2ec6494c7dead3584f0ccb7f4664eb7f0e397310b0871500b3a269f534d8bcfa0f245f0d69abb5b5e744c12e176e34838201cfb108fba0b5e104946490ce" },
                { "ru", "33708f4f6c8c9b601cd3552b8d7211639dd311d2d3a273ceaa6d2e078c220af3b390ed473ac3030d51beff5370572376317cc510edc9c67d288816df04d6f4a7" },
                { "sat", "b1157b0f48ca4ec3c97c93d3627276a804fa5f14424184f424aa9da3cec0d332921fcaa138d035804c2452ec2afe425d034674b9c5b70bcacd4bd1ac883a08ca" },
                { "sc", "db5bc198a84fd7ca91e2bd913063827c5cc6d544fa9b25f4ccc6313d722d1b781ddda7535db086d181790fd93898a22f0e2e25cb670e52ccd2f30669ce5cc784" },
                { "sco", "0f9654470164f83243ad4de9c76ade101e1c96fe0b24b4e94d138dfad92d02b48fb0138efd8484651756a94566a94e95600b5d0d39d8de512fc75912b07d0d8e" },
                { "si", "5afebb8bd63cec4ac3c044abf3c96663844a2044ac0de77ff500e4918da52d496a8d71db23100e7b97fc7968920ee36fb42fdf30a52cd07bb7e8af94cc6bc458" },
                { "sk", "cb0b80d4c147dd85a66cc70cb3231527c9db32f19dd2c1cdec876bb44acd5b004a0704a70bc72b96acc1e3bdd6133432f164c1c51089b727672333f065d4c516" },
                { "skr", "46a9dd8c264ae45c890fa663bf156298f1922c646981b1eee8a126fb4d013a6d5b5abab75849a6e4afbf63b1b094ee0f8dc4573068da21c417e15c9fc88027c6" },
                { "sl", "73e74cc2e4bd07a6725594ba357c8bcf2996e5ec37560edcc2f40db413923ffb01db579c19bbb5677d5d645b0d88212d3ab33e43714da553b342ca4a5a383a76" },
                { "son", "d36b0ac0fd51999ea5baba33bb33809c3b72688907c68a47d63db1a63d02fd32145a10f633804567e4909bcb4b7baec000c6e33902e84b8f4e766c89ef07262a" },
                { "sq", "6b7eebf399ff2e6116d4f0109cdf87638ae6a24062ff7b1a3ca9f9b57aee2f3bdb6b5790497c1dbb0acde9ee4b8fc4cad87e23ff122098426e5308e1d096cded" },
                { "sr", "2f0c3de1bd0b7598b26664a822a4bac8483a3204c8cf40cd0e6286277f334cbc1582c3e78f0560d291ff65b34ff87702d944e019857ac4f5913db15b9873809e" },
                { "sv-SE", "bfec685e4a76cc83030bd71e5070798075033e104de2582e38137d9ef6e19c1e60450b671e32a39478ec4146e83660b18dbddf22551d08ca3ee64ebe9db715e5" },
                { "szl", "c086fc9572eb9c76257c6b393506444fc3ff05ac6ae049a24e6f9c699a751ab697c0edebf505b65bd83cec1f705d9953bf69dffb4f06ba7a76683107e3664e36" },
                { "ta", "da500cbc006249d495ca382c4875178f4817c75dd2e5e2ddc24a4f3c746ad43f870b97bec9a0ba16d6c9f1244ae3bd00652661e5e6ec28f82096f8ef2a6fc431" },
                { "te", "3faa3f84829342c31568dfb28037659180e88625e6239a131f484558911f3ed19d6d69ccda72752759525ce89d4912b4815b956847255eb71ce9a690008f8d49" },
                { "tg", "c160abecf5342875c5f01077148812abf4ef3da53e833da9c0963e36b0f22ee377c74335351e0f30463b6518e81ed6f7e805c18f81e69f24655f21670e241fd3" },
                { "th", "9d5f6437887a20a9fb636ea7a5b4e437c90f728201507c99e81683b290dfa0c91b164790ea5307ebbcd1f5f8f0d54a12ca1a51e6e57a637b627277e16ddaede7" },
                { "tl", "69e2c03282f0377f8a8402447014393893872fef5f3517d8d8d3b2be034c82f65d4a59e69372832af0aa582f2c3d0fa5496dde359434e878ec14c3af2a27f077" },
                { "tr", "1e74d0e69647c47bbc362c0b387f2ddb4e6f06ab97e68e15c7a09c4734812bca522d293b5480f1ab2ddadeb1d2d1291e2ffd42c4c235248195005e79f5b095aa" },
                { "trs", "e4e2f90d5045161a9d2685db403e93082f8c91e51766275fa4d93d4f92c2f0e93f887762cf58cb019c95aa3c927baa71885e2d06f5a108be91dfc7857b56386c" },
                { "uk", "19122977439e40239f133782cd464b9f62a7575696fceb4b47c048b5ef02ffbc770a354ea76db9ac29b8c4f2be3c00a78865d46de2e16746a08f8fb1d0f6cf4a" },
                { "ur", "3ecb283f4381dd9a5e67ca833ce76e21b700dc31164ec01c492dc135fd86f1270a74777e018357ca010bb61b0f382fbaed4e673d2a78f9a9c30e674fb7afaca2" },
                { "uz", "3072ae46e5095cedab8975aed5a10e16a531c51e786d19eb0d976d1fcd63a60fe684289964dc8803aa79b6a9a3115792f51fbf92da8ea0bc7d3fdfac842104cf" },
                { "vi", "474e57f1f562c6dca9fb5705f4404473a62ed5eda7a3335bf4b278e24a5f17fc782e916ca0277ae3d4eda3989f7ba7f6f6907353c022643425d82b7f2430a507" },
                { "xh", "7f5f0ae423923ce95885855516d8573c240b7ef28598dcab2956c1ecc2c4f048f4c1d7c43b3e521f922586d64f88ce98d9b6ea0a6a370a038d1190900044f65c" },
                { "zh-CN", "319da313020519541c76470ae520c106c7cfbba6a5c7141e2c0a568c7a601a6bb839ad65f86c69c42504353360e680cdc09a60cdd71bddf8f90efa6a9e517ea0" },
                { "zh-TW", "63418c0abd8c0db411d1b48b6628dbbf298e2085bf0534a54c127863a403eede18e52bb581d166962ff4b91a406af895e208955516ac19106f95c4453e0f80c5" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.8.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "3cf851e7d6308221d7a5deb4092fa7eb624ed519da0ddc55a9a0c611aec30c13b66da2a64e134ebc1696c69f0e026aa7e5613a7293cac5016e9aef7d2484d009" },
                { "af", "ab509c39969dc9c12e93d72f75ac12614156e0508514ab3a69cdce9baddd118397e9f44ac1a45d10a86d142092aa52f7fda1c4b52d217f3e47920a61f38798ba" },
                { "an", "ea3f37d2ef3bbf39ce1b1f430875f914ee40041b88f3b2409f1ea97ee7500c19e201b56edebdf0a9df98a4bd8bf8e7b22fe68ddd87db5bfad8b1868b8e13c87b" },
                { "ar", "a1d4fe17941c1860efab2ff7e9df2b42a4f18ca7ee6487d9773c3a0d4544543dcf224d33a50d7c58acced1c6e5c7466fb0574bc975e8d45bbe2bced5a231bbf3" },
                { "ast", "db63df35840b4894caf5391fd1ff05257467f1da908296961a7343c7fc766ccf1a6a705cf4d5ddd4e3b97e69236faa614d387e7c1fc20148cd43fb8e3d36aa33" },
                { "az", "9c1f51872fd09780b5a23450a8b17eb20112a32287137e5f1f244000c98c29840163a1b391f3ddb9b7c4cfe15b618e67e0a42f33ec791a9d4f7c0d49b404cd27" },
                { "be", "97784396338c4f1677ddf4e932a9c02874568300b6f0bb2b5a61ab0a38d4667b1f906b61eb2c8ee78c7894655c61743dde7119bec97f223df17dce92261a1ab3" },
                { "bg", "39ed6aa62669b58b46a321ce90d62bb44d9dd87ae53468caf6552fbbf250dffdd1c76f347b0f180ad90c6dafd2d2fca47543f25bd2e958768fe2a54535dab1d8" },
                { "bn", "f538f574488e1916776c8f0ea4aadfbaee4830e018e5baa0bd2d3a9b1e1cc650b0608e90ffbb8467087830d2220a52741cc70ce690a96b5a6a0adb6e5925d2b7" },
                { "br", "3af311e1f3c7e9468a7963dab851116bcc35a6747d78abcd9573d8270633aa7c098e302cb72e9107f844cc025080c82fe13d5a1ed28caebd3a8d8bcbf999c923" },
                { "bs", "47073b8d8277bfb967a5f863d353453375a189124f620daf0e71c3daab54e0a792a4b2fd53fb5123065e01d3f518ce69626b5b482b2a2c52d47e2bb6fdb6f21f" },
                { "ca", "f4f9f1057f87f4809963a79f7ae1b80edc5d09b9ea5991127ef40a37dea8ea7d40ca4810488167f1f15b70bd19ce5bf34ade83944c0e838de0f80f754ae2a6c6" },
                { "cak", "37dad75f6e5f0d3064ef9a317b7a2864a3cb37a03ce1eb302fd3424d6e39f29f17c7f96bc3d1e865bd409158c731b036180be29c778eb8e04d74aa878c054e65" },
                { "cs", "150e1f346e2e796b655dc82562cd5f8941f12b199d7b03f697cd890c04c0f7892ea546c97aafdc78ad9da7a19e86d58b14aac68466364c00b053c494a8430a64" },
                { "cy", "9863b786ddbbb9e75879c734bb327e425f2f635d9c03759132ea9394492c396382f74c96cc0e62ec47c00f388425ba82deed9f8e420a719acf4f5acc41270b7c" },
                { "da", "db116ad301b7d6a70e745fa1e0686a160c826941a11095457a988096a550e3291d33de58aad6896b3eb5ccdbd3a520b917db254dfa917597b85ac3f1587bc08d" },
                { "de", "9c837e338e957a7e35b857dbcbea33f30147529a75161a599c1b67457c72b81fe6a50288e99f87a095ec7f3954b28dc69400ab7b7ce9a290e67986c258136c88" },
                { "dsb", "2efd2b434749c6a77c5d2c87fb4099636292d66fbc63f72d2602b76eff855ad27f6880e34eceecff327dbab64d32e087536cdf630c45abd7df473e16546cc161" },
                { "el", "4c85833d1f6f04c910eec631b664274aae0a1ff83fd9e89cc0795daef3a0b15dcb11b2784ddd93a119fd62be3aaa595eb00d3a5eb81d05159f5a13bd9584770a" },
                { "en-CA", "0fa36d30c1ad4257f902a27b3ce90af6fb519a5c0c3d45bf3bd758637b54b236de8801b225ac1a883db6f32feea6c93e25e028bd8f5a6ae4091d6e5c1375e5ee" },
                { "en-GB", "ecc304ed47ced2cb501dab91814f0e80afa8f4d9e2f135de764af7bf135abfbf190503bd4b9df235b1238030598c16e7ca02ddea57bdcc634372c8d9505b3c86" },
                { "en-US", "7532173b7cc92dcc9e090234861b78767e85d576a90e2445fdab4828e527246a5e3184cc211b56c99569956623c7a12cb88a0105d614bc9ffa5233ae56cb12e5" },
                { "eo", "e0c609ce5cdec3b066154b4b9f13f30a60f78fd38b7f216983b333b80982d439ea5357da0d5ed3cb6e74cc0ba71029cc5e10006bddee3f7d104a06f348fdd6eb" },
                { "es-AR", "42b24e30edc6e2e2454837b58a4460bb4915dd41fd9d35522fe057bd307d75ad1e0323ef708986151ae38304ca22fd4f6320a020e1c495cf261c1cf4b9650059" },
                { "es-CL", "f028a5c13616e0a0ca2c1f1fb0d9e1563ff5528b713f7548be0307aec42dbe8a1f4a89c3bb52b57668be1aadca40d2b68cc62919dafb95435f8b499f385ac592" },
                { "es-ES", "5c426bbf4b138be4d8171b73e65bdaccceded35c2439d224500fe352332e17dcd6a49c768adc6b831dd508632e01aca2ee5da056d69e31de8663020c3ca0abc6" },
                { "es-MX", "670e14595f5bbf524d265284f4d18ba90d9fa24e58dcaf4d1483dcaf154115323c28f6b7f73da9228275c0899174105fc7e3ee7c78c41b0657787a8e4584b15e" },
                { "et", "aa4f5ee73d2f76d15d578ea816bcfb02e59fcf983c5546fd190dd1b558e8a1ffdd78001d86e3247145d12a1d0a96c5a90f0652bd2415aa070cbc72caa0e29c7b" },
                { "eu", "d7f757c7b1141c04e60ded2b494cb0c2f31f4361a82e20cb5b66e32d8cd5de3258974ef4c3313ed89ebfcd4f46d8e5a92de529175851fefb77e022e560c9828e" },
                { "fa", "2de889570394950ea97657a45d23d04868195190ae66b45c4ff8bcc4b197bcc7baa14539af7472e300df0146d7e28575917f0a5729ae6a78116debeca425f363" },
                { "ff", "b47a8896b4b8e5cb2f0dc67b181f2aa37356bd510e23191a60410fbbf173865096fbab35de31e6d3164a1a4d41ea5a6a0cf928fa2aca94b708d2e4b804b04e0f" },
                { "fi", "ab3c259753f56621a4c7d64688c0f04087e8c4b3ff5e49636f8e9795d7d22c6d62b4ff686c0ef7cf0ec2405ba68faf294754ef2c741becee479c033959fabbd9" },
                { "fr", "7476e87866d226b62f01002a81a2702578d654f3dd13f7c9bfb13b05287b23db3978862070d457441da8fa1a3fdf4e5b2868cf0874033095359a4c86fc2af320" },
                { "fur", "900d4b2d403a4a1b8d69574e3be1a9e43e47a18d290d04d68f58b112438346c57a258b9d0f8eb07e5342ffebc12467f1570f04d325985084692ddd354835fb8e" },
                { "fy-NL", "10763a779cffb5d8f18a8d0ee9c4a447e919bbe85a857ec9f80fe27a0ab571da6df61e1b00385c1877509bd13d54880ece86383e901b24d9aa522a9903287cfe" },
                { "ga-IE", "e2dd868c5be0a6e1f48a145e73c196e4fe82ae7da94c49c9300d8d40f364eda9ea750f17f1c95c56be076136bbbe2f8076e56d8708ec8c51541331d523e2ca6d" },
                { "gd", "3e5be21a022ebc6b3250eba18f6517297fa3021277e6acbbeffe33b33cce84d7ff1b41ba63aa6f147571c7b0251bd48f4f1391314e33f6c72a5ebfed636d5036" },
                { "gl", "1769c85c762bbc7e51bcf7391171254837553bb803ae5b683b94c7a0cb59f638f377c29348c516711746255570b9425ca09b8962c7e35487fca63102d2428921" },
                { "gn", "acd2e65ceb5aa0d3534495ab40cf2ee546a8317c182c478c4af138328f73ae6f5be8176fa2711a628ef997e5967cd30254a5ec741eb8323d134c59ec0f82df0a" },
                { "gu-IN", "a9ad966821ed8c5e3b4e6715dc5d5aa70da7bbf31a2e5724802760f7b1e5193648305d96918bd100e7bc33d823bee370a9bc9894295db9ae581aa7062f0e1a16" },
                { "he", "78fbdb85d404db89000ed3b265c46c8bd9c1f1819dce532511a39e8c463aa92f009725bc51e6fe68d196ae21674538657a6705165aaa264d24a0ebfc3d00fba9" },
                { "hi-IN", "38a01945988c2bc613dec8f99820382053a64a9a321957d145df7721ec5aacc991dc56b5f6dc09e0255ab9b3516baba34db08027cf51b553bad258cc77397ecc" },
                { "hr", "1e0bf2fd61693fd8c2eb65214594f22fe395996bab2c1941aae6cd988921f9385eb6dbf7169eb5c3ca6ea3b8b2fded07b3e6b65b67b304a915002d0c218ea1c1" },
                { "hsb", "5d355e4519bee1d7795f0ad79e9056d67e5bf4607c1b992c92c5f6a70fcffdc7365d28ba9d0c1049d8930e809ca711d13f2859016cdbbeb53b1fc620bf1c1339" },
                { "hu", "36ccc5e3bc64f66ccd5bcc6c83fe3d78050361d04c4b6aee62cbf1e104e7a41b9d8756db17fe82f909adae1886842c4dec7809b3eb5772b052ea0508d2b686b9" },
                { "hy-AM", "46a8a766f4b8ee8043b8ed0244638f96be5726ee7e64283da11bd1e01fb0aab2b4fc5384ff8d7294cfb913556341d638dc21ef47c87d6c0eb97d5eb55e5fa41a" },
                { "ia", "a5f7c3988378fc23c726c0c083d1184afa44df5fa01dc4ea56984d71be3a0d8bb585903533a1887615fff33947986d605f1c3d83716d79b7dd02d577c3cc170b" },
                { "id", "71fd1cd31118ce5f7b94d6c98efc50648a650d9753d4aa9aafcede0c5614794fb84fe50537b607894886fec9f5367e62a71cb2a7f69027984cdadd307ffddfba" },
                { "is", "3bb2bdf649f7060f480486a0939697bd2794148fde147a820626f9bd3c0dfb3f80a9f98fa74628b8d7ef405c9456f7f0f1ad3b21245f0edf48989e72d9a8af6a" },
                { "it", "dd07ee1664344a6b7c66e3e0c504e89cec7a0aaf45a0e3e044d197c620451cb7b5b5880adbc8ee870cc013dbfc979cb1864516e9a438743c921d2ea6bdcac811" },
                { "ja", "41105aa15c60b3006c6dafaa4bd9714ca93f57366039e5f96a747f7a30b23113df6133cc2459093487a71ad08a816c0dfe6d369411768031d526d91f85a888c8" },
                { "ka", "d8f87fcd400c5c9f8d47eeba4c713c71a96c618b737e0023ff7af09c4bee06c46520e4da05a7e75c055430c630fae2f5f2bfe752ae64aadde8fca769065ce8cf" },
                { "kab", "66b47a84bc1ad8647d31df6e2dd06dff807c8be52cd444a53390b7a5de002a8826775e135b389a93b52055e915fcc0282afd112aac951406129e7ed60738d1cc" },
                { "kk", "92bac86041eea1b0a5c87399c5e83b3da704274f546e39b92a7ae82d4855c723505b2836ce9a1653ed0162be246780633e89a06883f358017501cd0cc935942a" },
                { "km", "315f1c260058552a2bc7f4e72c486d21a68e24ca33e681bb3a797277021396673e44b28ef11e404475731b5900a2ca028bf5f1e138eae08dc26fe9505dd9cbc0" },
                { "kn", "39a704de6276affe1910505ab1b04c7b3205be274edf877ccbe27e6c329e53a4792134d143a50e12c4c8f15d766fe3ec88bf4d1d40dd57ff777ae4a661ec8145" },
                { "ko", "5c8eaee0a9e25411ed54f01325622032453b0bf59281576228710eaf3750de6b4ecd4a2fa32c91dad785141b2d27de70e5e6d73581938aa65aac7146ce11b7b7" },
                { "lij", "703071a2c0cf2cd78cff43d7fd468058c6210214f19876ae8c4936b6795fd00b8bb7c7d05cd0a95f11e3caff06cf0406dc7f1a38b5dbd2d8a68ce3f71026a3ca" },
                { "lt", "a2d39edc5de7787dada21bc9b87dd2d789e5119fc26487df0b9ed00662f4f3d805c3d508294ad3cc1df32d5ccff87e16f6e18bd8b8a017927d0d2d5f2cc09d31" },
                { "lv", "3e78ddb0e5a67cdfdd8481612a60717abbd7668a1e71926f5bc33aed20954afe284453d70c3b8362362135f9b814b0580fd2dc41c2d9818dd4281de353eba29b" },
                { "mk", "b383ab632074c11197756ca9f5b24a7df43284f6803a112e4f22e7eb97bbb0863d4d1ff195751c6cbc36ab883bbe6e2aaefab959e76adab5afcf3fee22314069" },
                { "mr", "7770ccf2ce290add747b5c25bd070cb09472818fdc6858ba03ba0f51110273a74d6c98733490f06002580c316b2c4c9b7d2aedb4276fa8faf4daa0b7e2f247bf" },
                { "ms", "a4b989ab6898b8b130dd91cdef394aaf89c01e479c7d8d34bdd884329fc268fe798287116394d42b7f0e51b00673a35efa8c4175b7fd6cff8725a5683cebbb69" },
                { "my", "73d5c4dc153f0e481a7ba31de08d32c7de91497f407990c630ebb4d81f14a07a34c79c343b582bd05fc4e6070031cfc42f5acbc01fa3337d910e51671d27b4f7" },
                { "nb-NO", "8437873dd3140deba88fb4df9ae90fbaaf3c774d31f915ad87d26e090b65cb95f8e0b5e6e2b728ad541eedd880301310e46476a12c2eb4c2bdc82eb7f4685fd9" },
                { "ne-NP", "453f04fef9d7f61e2a493923fb2b28c719af8e60cbd70efd79110e540cbb09f9d65d4e432f0faa9a239fa419db1521136f13798fc6b836d4eb4439a095eeb3c1" },
                { "nl", "7d42d48cbb3f9c2f8fc8925109a27c27c4e8a11471b757159b9fa57d7903d750eeb5c4dd53905f441d46fc1a68b0b3a87435fe5c3b53dcea5776fe15017becf7" },
                { "nn-NO", "50c1156c3e291a779e1133cea915adff4544d1befa0db098fe01aa2fd5a87df8952cd65fc77aacbdf7b75380d22ad8989497f1364ed34538fe11a4be3298f3b4" },
                { "oc", "2175185a54363bf40fc981eb800e088a26a51b43b4490a8100af8ca8d5a4b589c940c5e638a99c426823bcf5122bcdc73eb5e9edce91309fe8e42a9ab06ce49b" },
                { "pa-IN", "75648f79becdf0fe5439f374b4d770eab58ccddf9efd6390a95bb40cb170bbd2ca9f329111ae87f412d8f52737b1189fb561b14efdf67c88aa255dd08fc0a537" },
                { "pl", "7432a423b0b390f61656f991a87ac3d21ab946465a3f5827a8bc93e86f947886b2b4927aa809613f69e8f2441317625dfa4111df96fba64ba36a23da3de9cad7" },
                { "pt-BR", "c9b5aba6856d90bbc1229e97a1e92a25c0644e4397ad8849f614135c3db00264467f47b08e48a359075cd0e7eab49a93891b090e3a2ea8dbfca313819486157c" },
                { "pt-PT", "1c87be489446e9bc0a2a86772c1c19ec4fbd7b8ded6aadf324043edbd763412b105a8fe3db63fc8ff3064633000aa8668a8e0d3b2101f6d79c829071c3de5aba" },
                { "rm", "5f6cd9152e6e3c57f5f6ded192a4b78d2046be9437551cb719b81ff2e58622fc296c3a910741edb9b49f4024adbd5ad091561542029c7c9ec9e04398f68d6e75" },
                { "ro", "ec2d71c2fb93d5c4ad81e6a45455f185a48bba6bf8eddc96bbef508ffb29f23053ba55829cd5bf7d19445bcde863755ee9d8a03294f06058a1bfe27b57e15962" },
                { "ru", "95dad7b62f5c888a43c26eb2ca727be1131455f022aa1036fff9bed3ffef42aab3841d1a12d800e4fa9f6292812807ba508aae850ec8f72651798fe44c4daaf9" },
                { "sat", "2de8ee207ff89c7c9934ee72adbc7cfa7af5c2ddc291cdb0fc5efc93722ca98321af03786c700fad51b717cd223f949af42bf80cd618bc1bdd5b5432ac12c036" },
                { "sc", "4ef16cffed03a8152e38a8caf6c16bcfed682a31e08daefdf64121256d7c76d70309902da7cad7b3c3e4bb4fc09caf06cf44c850836486c2a46500d239226f9f" },
                { "sco", "b38ca1b6425f3d105c3bf9496de8286e0c97693bb7d0a85d51d60346b3141dead1124aad048fe4cdb33887612ddac3a58f0380027e32a5366d6623a264445240" },
                { "si", "ad6b03ff5199e567ddff4ae5275214e05583ce56ce27343f19e5351017b92292df2e373db75d851c9babd27378205c4c97b70276fd4b6f44aa8f39463910376d" },
                { "sk", "e3fbedb7eae296da8a925f337966d3e0bd0390782202e11a32f94c5de7be486a46cd3ce53342ca3aa86249c9416da672e58569a0e90037d635cd7026435514f3" },
                { "skr", "dccc6872acfab140a8dbbf94b2492b9e9e00acf2346ae8c90c7b70fea196616c27a2a87a0a3d78b6385c1122be08ad87fa320e92482110c2ceecc69c665fa1ab" },
                { "sl", "d398f446aa40b72304363858d9482eef0f0f5227e2ff77f165f38241a6272aa3a75ecc04db4b2edd797de910f04340707e21f6aebd3721d50a829be2b459684a" },
                { "son", "7783e713d381d4c8fd94c36e9ccc782b512c2408596a04ed3dbb472788649dddc5bc61441c970db2967b68fbd061ea2b96fd03bd1c895875e8673e56d8fa98ff" },
                { "sq", "550692a43b66d2326c3e4f5d1c499ca1c592e343e5bd7614790fa773057b6d4ba457e47fd8687ad56bcd8475d5ffb7d3b43eb9d720869010180cf398d1a9f04c" },
                { "sr", "f4b2498e5abe6d95f2068f90d3e3203d73f6ef750e000eec8ebe42ae34ab7aa1593fab574139344e8ed4fbacf1905489d3eab2c76c9acc51ca5de28981cdc9dd" },
                { "sv-SE", "02bb9e73ee75f567cfae1b621828b5c82644f04d781bc8b59f48523bb32d92cea9c2f94e6d4dee9d9b44672846349e1a187d36d4894805ec4d50123e3ff1caf6" },
                { "szl", "e6cb3d69e2294b31c58f1f50125e3a2ff638de99683b60d5cf2d431437812fa915402e3a3e0c02b0b2bd1b05ba2210029ceab8a6327ec6cc3ab54ff124209619" },
                { "ta", "3100c7486e2b0f19a00949b7b7a3101cca335ff5eeb5129e4c431e0cff4e5b42b731e4df49f926a99e64922a00c9726e15d079d9aa9409189c3a8fffe1b1dbfc" },
                { "te", "1e3bcc8eb3bc2d378f181c2bc5420f87e4c6695adf706ddf85c2e468dc12803f383ad86700a81733e7621e384f96b233503c1b7de71f316feebe92715509346f" },
                { "tg", "8148f495c3863e4c47ebae851a4d256907e9b9dd2bb436084ee449039432dc402683f0ff94ee6df07b62c2801bca55ee9f22b8caf0be726ceedcba3b3babeb67" },
                { "th", "f1242c19202e8a03006b9abb81bb1ac0c19a9d396eab449eb19b20bd738a984ba9f624cbebf5b0b570308f517455fc2d26bc810abc762476ac6d2f3bef903b20" },
                { "tl", "70c76c01ada9ffe3d895176f9e93d84d5aba3cbd2afd87d1ecca9459204a5f39fc1dcd2aff76662fe9b6def7395b8521717a8d572979b6064aea69c865abf093" },
                { "tr", "fa5241473cb812a78fd33d36fc33c6f4d8162f96059e6046236ee3c9452d514d8ea65d499677ccfc733956c606c2fb1eb1bdcd00446e6246c1f0c5d4094a80bc" },
                { "trs", "55d0a3092d64ec825d0fb2307e2346aee88df3ec9954c460956713ff028dc5462e36cc6a7a8173e7da9f951e2ea90ca2bc0c205f658534358fe525554f16fd4c" },
                { "uk", "ccccbcd4442603aec6ca4db1ed0b2b4a7ab2ec0b22b42c3e19aaec13cd87ac0632e1c4100f303a2803a4f18d326187f97a6a7d19c1f3107a2c20f2d095447d51" },
                { "ur", "1ba901c55557dd7b06e0fcf1456d1ceacf1459eb11350987d2e39c1468a64ccec1ac72885587b2886540af9249b70f8f2ef6e1738725eab60c5c37a2130dcb75" },
                { "uz", "184a44e9b342ec52319c0c8d573323f8c1a1d8d7d467e7f4f12e0b5636d975a6eabcd57aa6557916e5a1dfd650f1dbba5fd409006970dda9212003098a3a3b63" },
                { "vi", "86c449b4efdacccfb11f94458dcfb1bb78cb2e92bf93a8242812a228130eded1d49a79f863d5a714c96b729de6d3dd0ff78837f4dc7c5ed90718d8adcca2fe60" },
                { "xh", "530d9a6ed9517aa25dc9a764f87a55134a84c9c86a999e58f735246a8998f55d7bbd3e3f2e852da4d7ed5f41d960a4a82a4225b80688658ad2faa22eeda132f6" },
                { "zh-CN", "89ddc04b49ac427951aa654bf26bcfc944d92c88360a7ab18ea608865a029203f28fa2b395a9ba95b06ce167c1214afb75c4a5e5f0e24854783f1579671f87ad" },
                { "zh-TW", "82f2b70cdfee6d394816e335872db59d50cfa7ac05e2c87cf211a17cb7df73064a6eca22d223ee0220f7bf9e8c80da6a7ca32956ab7378b6f399eccb6ffb7ebb" }
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
