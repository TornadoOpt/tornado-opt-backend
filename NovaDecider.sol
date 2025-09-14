// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

/*
    Sonobe's Nova + CycleFold decider verifier.
    Joint effort by 0xPARC & PSE.

    More details at https://github.com/privacy-scaling-explorations/sonobe
    Usage and design documentation at https://privacy-scaling-explorations.github.io/sonobe-docs/

    Uses the https://github.com/iden3/snarkjs/blob/master/templates/verifier_groth16.sol.ejs
    Groth16 verifier implementation and a KZG10 Solidity template adapted from
    https://github.com/weijiekoh/libkzg.
    Additionally we implement the NovaDecider contract, which combines the
    Groth16 and KZG10 verifiers to verify the zkSNARK proofs coming from
    Nova+CycleFold folding.
*/


/* =============================== */
/* KZG10 verifier methods */
/**
 * @author  Privacy and Scaling Explorations team - pse.dev
 * @dev     Contains utility functions for ops in BN254; in G_1 mostly.
 * @notice  Forked from https://github.com/weijiekoh/libkzg.
 * Among others, a few of the changes we did on this fork were:
 * - Templating the pragma version
 * - Removing type wrappers and use uints instead
 * - Performing changes on arg types
 * - Update some of the `require` statements 
 * - Use the bn254 scalar field instead of checking for overflow on the babyjub prime
 * - In batch checking, we compute auxiliary polynomials and their commitments at the same time.
 */
contract KZG10Verifier {

    // prime of field F_p over which y^2 = x^3 + 3 is defined
    uint256 public constant BN254_PRIME_FIELD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 public constant BN254_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /**
     * @notice  Performs scalar multiplication in G_1.
     * @param   p  G_1 point to multiply
     * @param   s  Scalar to multiply by
     * @return  r  G_1 point p multiplied by scalar s
     */
    function mulScalar(uint256[2] memory p, uint256 s) internal view returns (uint256[2] memory r) {
        uint256[3] memory input;
        input[0] = p[0];
        input[1] = p[1];
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40)
            switch success
            case 0 { invalid() }
        }
        require(success, "bn254: scalar mul failed");
    }

    /**
     * @notice  Negates a point in G_1.
     * @param   p  G_1 point to negate
     * @return  uint256[2]  G_1 point -p
     */
    function negate(uint256[2] memory p) internal pure returns (uint256[2] memory) {
        if (p[0] == 0 && p[1] == 0) {
            return p;
        }
        return [p[0], BN254_PRIME_FIELD - (p[1] % BN254_PRIME_FIELD)];
    }

    /**
     * @notice  Adds two points in G_1.
     * @param   p1  G_1 point 1
     * @param   p2  G_1 point 2
     * @return  r  G_1 point p1 + p2
     */
    function add(uint256[2] memory p1, uint256[2] memory p2) internal view returns (uint256[2] memory r) {
        bool success;
        uint256[4] memory input = [p1[0], p1[1], p2[0], p2[1]];
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0x80, r, 0x40)
            switch success
            case 0 { invalid() }
        }

        require(success, "bn254: point add failed");
    }

    /**
     * @notice  Computes the pairing check e(p1, p2) * e(p3, p4) == 1
     * @dev     Note that G_2 points a*i + b are encoded as two elements of F_p, (a, b)
     * @param   a_1  G_1 point 1
     * @param   a_2  G_2 point 1
     * @param   b_1  G_1 point 2
     * @param   b_2  G_2 point 2
     * @return  result  true if pairing check is successful
     */
    function pairing(uint256[2] memory a_1, uint256[2][2] memory a_2, uint256[2] memory b_1, uint256[2][2] memory b_2)
        internal
        view
        returns (bool result)
    {
        uint256[12] memory input = [
            a_1[0],
            a_1[1],
            a_2[0][1], // imaginary part first
            a_2[0][0],
            a_2[1][1], // imaginary part first
            a_2[1][0],
            b_1[0],
            b_1[1],
            b_2[0][1], // imaginary part first
            b_2[0][0],
            b_2[1][1], // imaginary part first
            b_2[1][0]
        ];

        uint256[1] memory out;
        bool success;

        assembly {
            success := staticcall(sub(gas(), 2000), 8, input, 0x180, out, 0x20)
            switch success
            case 0 { invalid() }
        }

        require(success, "bn254: pairing failed");

        return out[0] == 1;
    }

    uint256[2] G_1 = [
            19105230784230701148780516635996780480662558460399214766723437833066991099163,
            20628488457886956201033194127442890560947267799230122906968533927574056950930
    ];
    uint256[2][2] G_2 = [
        [
            8439412050392535277379118777999631613708332799048806588472706413426111220801,
            10066673830968449824250516551783549502108373182923200206719545496749823255144
        ],
        [
            1017749586560468319103913726882077862896408516819634534270295062521788241806,
            2362669120177278820997579760904544524943556521056617039464944302619990015391
        ]
    ];
    uint256[2][2] VK = [
        [
            11464844574970755759255178100409615801110755768276458427679146721841102786441,
            11231337833926820255743041547384700890646167615275686320671098733540035231209
        ],
        [
            16831533695052149214993934431007117119038050109184391179378567728994473285963,
            20666865945548187106976909785560922014806792357669674095856344239532836762928
        ]
    ];

    

    /**
     * @notice  Verifies a single point evaluation proof. Function name follows `ark-poly`.
     * @dev     To avoid ops in G_2, we slightly tweak how the verification is done.
     * @param   c  G_1 point commitment to polynomial.
     * @param   pi G_1 point proof.
     * @param   x  Value to prove evaluation of polynomial at.
     * @param   y  Evaluation poly(x).
     * @return  result Indicates if KZG proof is correct.
     */
    function check(uint256[2] calldata c, uint256[2] calldata pi, uint256 x, uint256 y)
        public
        view
        returns (bool result)
    {
        //
        // we want to:
        //      1. avoid gas intensive ops in G2
        //      2. format the pairing check in line with what the evm opcode expects.
        //
        // we can do this by tweaking the KZG check to be:
        //
        //          e(pi, vk - x * g2) = e(c - y * g1, g2) [initial check]
        //          e(pi, vk - x * g2) * e(c - y * g1, g2)^{-1} = 1
        //          e(pi, vk - x * g2) * e(-c + y * g1, g2) = 1 [bilinearity of pairing for all subsequent steps]
        //          e(pi, vk) * e(pi, -x * g2) * e(-c + y * g1, g2) = 1
        //          e(pi, vk) * e(-x * pi, g2) * e(-c + y * g1, g2) = 1
        //          e(pi, vk) * e(x * -pi - c + y * g1, g2) = 1 [done]
        //                        |_   rhs_pairing  _|
        //
        uint256[2] memory rhs_pairing =
            add(mulScalar(negate(pi), x), add(negate(c), mulScalar(G_1, y)));
        return pairing(pi, VK, rhs_pairing, G_2);
    }

    function evalPolyAt(uint256[] memory _coefficients, uint256 _index) public pure returns (uint256) {
        uint256 m = BN254_SCALAR_FIELD;
        uint256 result = 0;
        uint256 powerOfX = 1;

        for (uint256 i = 0; i < _coefficients.length; i++) {
            uint256 coeff = _coefficients[i];
            assembly {
                result := addmod(result, mulmod(powerOfX, coeff, m), m)
                powerOfX := mulmod(powerOfX, _index, m)
            }
        }
        return result;
    }

    
}

/* =============================== */
/* Groth16 verifier methods */
/*
    Copyright 2021 0KIMS association.

    * `solidity-verifiers` added comment
        This file is a template built out of [snarkJS](https://github.com/iden3/snarkjs) groth16 verifier.
        See the original ejs template [here](https://github.com/iden3/snarkjs/blob/master/templates/verifier_groth16.sol.ejs)
    *

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 14993921885163847874499427472566194652516176714676047306906300693039946863708;
    uint256 constant alphay  = 19702491146198006557814744226256064759251946171898012732774699965236293597465;
    uint256 constant betax1  = 17036801534805409421257913043799369872272213353648805386596584095074557044888;
    uint256 constant betax2  = 17970317750033554016795336571242068907446062467199258590996478370001116416473;
    uint256 constant betay1  = 11723060997402755895793207776497640148795279415319274719782093636155135120057;
    uint256 constant betay2  = 5908844499011525967351079004582582185974726215346357626160454531326935672636;
    uint256 constant gammax1 = 13962928978613971037711570668812834411261962088226121988418110545456226447062;
    uint256 constant gammax2 = 11921065904704149855289052370145673919547433655533773485138844933626278579323;
    uint256 constant gammay1 = 1647626842882754978267592165833297605328707589105199770581226558087143126224;
    uint256 constant gammay2 = 5177475329976348336957683170250766422405505164658275059908744232616683874671;
    uint256 constant deltax1 = 14115901069699975364876754667118213711577880167511069390626964056245690327361;
    uint256 constant deltax2 = 18281474295505081707411461013613748102528176760636897999172598964703432109164;
    uint256 constant deltay1 = 17757276987963693547474493266035293702711253514871769586578837308820177503266;
    uint256 constant deltay2 = 4631614783119204146731055124091529989232787735842805697495924356143024636418;

    
    uint256 constant IC0x = 17356091064374860589357894737462544671187627098729299007394882742435372057009;
    uint256 constant IC0y = 2589996151310936523202609756887824356973191287718690516124154375638657305946;
    
    uint256 constant IC1x = 11889830279771463500510403323660780571147753808487275089241656089244706174286;
    uint256 constant IC1y = 8976631338492168860457046913391379050879761326701068242577677526974294744257;
    
    uint256 constant IC2x = 4279812050931979079281100618577663515612970031856329811844007710005443052017;
    uint256 constant IC2y = 17818395888689046734957227543472820396278076707535162530090990658758914805249;
    
    uint256 constant IC3x = 17754296815079155251664870072160684429816237196436026897510724345256051991453;
    uint256 constant IC3y = 10155475445948948704570520269114844557388519329775116295640831059179964989507;
    
    uint256 constant IC4x = 11687835059259868219211494252841662800669864591347766614705152166510203096350;
    uint256 constant IC4y = 14123774093263088628670061265308095490081049664827324553380039945509996722927;
    
    uint256 constant IC5x = 9554908233281228666492682332794608409084209555581418796162768407670228958696;
    uint256 constant IC5y = 3765750057239811857123446255124729298634133297893294497444766507254121363224;
    
    uint256 constant IC6x = 11199127836510467373015644464306287859865844041812279294609520491107544608793;
    uint256 constant IC6y = 2106318493522741999886686497604843311544316860115295769969561422669832516244;
    
    uint256 constant IC7x = 15641505033530811145034633959746466359192566203816042012719962734336102567546;
    uint256 constant IC7y = 10984584473755228400701710423918391590001109777109521550490974070349451229720;
    
    uint256 constant IC8x = 2906683296806478431860760297872074386893643981302222309416337057725626886491;
    uint256 constant IC8y = 9391978108456871717258482456813423304872189812251414581086130400481498357150;
    
    uint256 constant IC9x = 21496145934068378645374523940940500801410063338021290968369131199582118775226;
    uint256 constant IC9y = 20135441392789277452414374466273756633825199789689206093979159231014835795843;
    
    uint256 constant IC10x = 16844066871954098345648096587123485995211603334488276409132094319393946519127;
    uint256 constant IC10y = 7842931709921794604221669937135536282343300023288300502823735901303231318592;
    
    uint256 constant IC11x = 21534568015732898324770727638173885464383256186075240954141453765506889157469;
    uint256 constant IC11y = 14038183706073782585225980482536923642105267171561001410602769557423516857200;
    
    uint256 constant IC12x = 7454677554197951916836672654263537107362264978789696904941651110958816475337;
    uint256 constant IC12y = 20695344596031080208836112007994735095939848216623402587528934099092331505342;
    
    uint256 constant IC13x = 6291074109249257133049509829163068186540514989282812094335924705334941402310;
    uint256 constant IC13y = 10215481478002074874737439831165656227745109975056818747041342802693859468057;
    
    uint256 constant IC14x = 10165797999722910773057821150052930884798115847675279788506879410326612907909;
    uint256 constant IC14y = 1176723748753419299852371474153670251531457669712994853650656658095829654251;
    
    uint256 constant IC15x = 15913761463473518819705751102505750988885288766485481301751016890130699776035;
    uint256 constant IC15y = 13019650237832132349692150495637848321470432854669212667091653714444022474089;
    
    uint256 constant IC16x = 4111493974005355483202968982339270316071720748264913072245808787791782820258;
    uint256 constant IC16y = 21626222960948112668323014004212631829953421847891297510823844175384145760299;
    
    uint256 constant IC17x = 6971906511410565691340874660724186950988799849305421133416593566233672773717;
    uint256 constant IC17y = 5263408649586815822163887796337373222976095989107270147448874714687614852202;
    
    uint256 constant IC18x = 12776207052262003825795940402823300748702584200319068748564565811974284701307;
    uint256 constant IC18y = 11550156343065192888517509817388724645670030368739602007970651052865179191839;
    
    uint256 constant IC19x = 10790756524112597125922481823103277288267134897713914163654054418856332281082;
    uint256 constant IC19y = 3723345712551422704764354064905239914445482945888517336358984617127396693439;
    
    uint256 constant IC20x = 21271721482522980404977351729497193782334619984532761804609439691227297660568;
    uint256 constant IC20y = 6665801607252490092206020026289374840370313912723039698591458872725755328645;
    
    uint256 constant IC21x = 5814116974605627915545271273079155468232573772800471920715313861645787650420;
    uint256 constant IC21y = 17915720974408851750123368468051527387927490398659481062412704278735176052693;
    
    uint256 constant IC22x = 8636831847787157112990090951691517852502634508151524172144711661997369497962;
    uint256 constant IC22y = 12297295064561546765005241157432161998337558371212804991905392841209465612530;
    
    uint256 constant IC23x = 5864085051494469959848795425248438969287251531269311878104030296038492196534;
    uint256 constant IC23y = 2073466580306090057185600245990245065063727275071711881428515455194800600767;
    
    uint256 constant IC24x = 14959443603484063307648381270449147192429914460193683949097569811472152755885;
    uint256 constant IC24y = 17365692762890942239407417266588915675204135733807323589409249545169080443272;
    
    uint256 constant IC25x = 5270624303864200250341552376404875854952549211497959562785638505089341172644;
    uint256 constant IC25y = 4177955588320497202250348791065013934883902266457415754281614019172551519189;
    
    uint256 constant IC26x = 5351237974122336002269056747467514784998392598431876366593558293710977223913;
    uint256 constant IC26y = 6118714268731597881185583017463154598242460960016378481466731582906644073564;
    
    uint256 constant IC27x = 5702649121190446198364141714121986077172852232563388115074938434792993060406;
    uint256 constant IC27y = 12459714990649159706190094969634690269457876018669519941340816523309740238577;
    
    uint256 constant IC28x = 7087906917262712151319066435429754715259985274620785993419261490981127232919;
    uint256 constant IC28y = 10876214251759009691722613395628917816237218562452051459295568751917107161189;
    
    uint256 constant IC29x = 2504865740197853520940839576846739073658692258420279520796828190085555219573;
    uint256 constant IC29y = 17860261801427022467526866405895698270186266917174037475332425497662806037322;
    
    uint256 constant IC30x = 442788848363140985767052310601354514520601864077020201720653920122956107049;
    uint256 constant IC30y = 13333455693548533762468165100821956870818479580520765921707103209764136170591;
    
    uint256 constant IC31x = 10742505249436520878712559827904823649163956123775652868660795459760988844096;
    uint256 constant IC31y = 499040355724957497388146836943462410639846604081179871143663300281036676480;
    
    uint256 constant IC32x = 20413978705860081134196559476831082481237222191802577647601826282938630007503;
    uint256 constant IC32y = 13916125187648526157104853786986331684056002001259776829161564674744423143296;
    
    uint256 constant IC33x = 9850201638151172397789789932966093858156409871961295842841424099865113593887;
    uint256 constant IC33y = 10697536589661580761075310822092383561889427766469571036572011424742431664097;
    
    uint256 constant IC34x = 2855369587790078936494519826874835999762897867796885102341153751261590643152;
    uint256 constant IC34y = 8495733213116683195548069038614250278793772663687811084592190649805142236770;
    
    uint256 constant IC35x = 15967860849567631344711824488764106747700442117235898670308811217070383818209;
    uint256 constant IC35y = 15827853097181792290268716442636141696853292522262691799979412987924535243402;
    
    uint256 constant IC36x = 17702743410508138407694640943631769833870889945324473368827172950393422625976;
    uint256 constant IC36y = 11763724974171798657113076992123448056385848597557935079061744731722014035057;
    
    uint256 constant IC37x = 14385272056717837901525314794612932191726158387017880605473346567034844003203;
    uint256 constant IC37y = 6755156893641304678171050412150430437344314733696524664632808657978152956005;
    
    uint256 constant IC38x = 19501772763113023157367814087426847231945638282600738893831539611651109559650;
    uint256 constant IC38y = 962623085570338874972865805756416275908681192780957834631018724720325983506;
    
    uint256 constant IC39x = 15098660785694321540876972302722028588656964147155182124065946832640264174790;
    uint256 constant IC39y = 20007482029858560392417770016021038775293119638370296552937848003285335418908;
    
    uint256 constant IC40x = 13689328478199835472458339247793743753982657084516183479984998862526045254436;
    uint256 constant IC40y = 1615534934982147580547256460234543979725717602237759012339799192209453029897;
    
    uint256 constant IC41x = 20545819440837576699745053163237199302355017286421480362489246411113618578569;
    uint256 constant IC41y = 16671265393867680939542275718245200048695896397102895644512016780988818838056;
    
    uint256 constant IC42x = 19978594914680647690838221547379862913933648603570724567433899747578304052222;
    uint256 constant IC42y = 14022594880928058857563201383808605781245810854062640861402522894801704543323;
    
    
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[42] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))
                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))
                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))
                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))
                g1_mulAccC(_pVk, IC35x, IC35y, calldataload(add(pubSignals, 1088)))
                g1_mulAccC(_pVk, IC36x, IC36y, calldataload(add(pubSignals, 1120)))
                g1_mulAccC(_pVk, IC37x, IC37y, calldataload(add(pubSignals, 1152)))
                g1_mulAccC(_pVk, IC38x, IC38y, calldataload(add(pubSignals, 1184)))
                g1_mulAccC(_pVk, IC39x, IC39y, calldataload(add(pubSignals, 1216)))
                g1_mulAccC(_pVk, IC40x, IC40y, calldataload(add(pubSignals, 1248)))
                g1_mulAccC(_pVk, IC41x, IC41y, calldataload(add(pubSignals, 1280)))
                g1_mulAccC(_pVk, IC42x, IC42y, calldataload(add(pubSignals, 1312)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            
            checkField(calldataload(add(_pubSignals, 960)))
            
            checkField(calldataload(add(_pubSignals, 992)))
            
            checkField(calldataload(add(_pubSignals, 1024)))
            
            checkField(calldataload(add(_pubSignals, 1056)))
            
            checkField(calldataload(add(_pubSignals, 1088)))
            
            checkField(calldataload(add(_pubSignals, 1120)))
            
            checkField(calldataload(add(_pubSignals, 1152)))
            
            checkField(calldataload(add(_pubSignals, 1184)))
            
            checkField(calldataload(add(_pubSignals, 1216)))
            
            checkField(calldataload(add(_pubSignals, 1248)))
            
            checkField(calldataload(add(_pubSignals, 1280)))
            
            checkField(calldataload(add(_pubSignals, 1312)))
            
            checkField(calldataload(add(_pubSignals, 1344)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            
            return(0, 0x20)
        }
    }
}


/* =============================== */
/* Nova+CycleFold Decider verifier */
/**
 * @notice  Computes the decomposition of a `uint256` into num_limbs limbs of bits_per_limb bits each.
 * @dev     Compatible with sonobe::folding-schemes::folding::circuits::nonnative::nonnative_field_to_field_elements.
 */
library LimbsDecomposition {
    function decompose(uint256 x) internal pure returns (uint256[5] memory) {
        uint256[5] memory limbs;
        for (uint8 i = 0; i < 5; i++) {
            limbs[i] = (x >> (55 * i)) & ((1 << 55) - 1);
        }
        return limbs;
    }
}

/**
 * @author  PSE & 0xPARC
 * @title   NovaDecider contract, for verifying Nova IVC SNARK proofs.
 * @dev     This is an askama template which, when templated, features a Groth16 and KZG10 verifiers from which this contract inherits.
 */
contract NovaDecider is Groth16Verifier, KZG10Verifier {
    /**
     * @notice  Computes the linear combination of a and b with r as the coefficient.
     * @dev     All ops are done mod the BN254 scalar field prime
     */
    function rlc(uint256 a, uint256 r, uint256 b) internal pure returns (uint256 result) {
        assembly {
            result := addmod(a, mulmod(r, b, BN254_SCALAR_FIELD), BN254_SCALAR_FIELD)
        }
    }

    /**
     * @notice  Verifies a nova cyclefold proof consisting of two KZG proofs and of a groth16 proof.
     * @dev     The selector of this function is "dynamic", since it depends on `z_len`.
     */
    function verifyNovaProof(
        // inputs are grouped to prevent errors due stack too deep
        uint256[7] calldata i_z0_zi, // [i, z0, zi] where |z0| == |zi|
        uint256[4] calldata U_i_cmW_U_i_cmE, // [U_i_cmW[2], U_i_cmE[2]]
        uint256[2] calldata u_i_cmW, // [u_i_cmW[2]]
        uint256[3] calldata cmT_r, // [cmT[2], r]
        uint256[2] calldata pA, // groth16 
        uint256[2][2] calldata pB, // groth16
        uint256[2] calldata pC, // groth16
        uint256[4] calldata challenge_W_challenge_E_kzg_evals, // [challenge_W, challenge_E, eval_W, eval_E]
        uint256[2][2] calldata kzg_proof // [proof_W, proof_E]
    ) public view returns (bool) {

        require(i_z0_zi[0] >= 2, "Folding: the number of folded steps should be at least 2");

        // from gamma_abc_len, we subtract 1. 
        uint256[42] memory public_inputs; 

        public_inputs[0] = 8434409165269547820994874210653501801464921024619655951650051565710923165693;
        public_inputs[1] = i_z0_zi[0];

        for (uint i = 0; i < 6; i++) {
            public_inputs[2 + i] = i_z0_zi[1 + i];
        }

        {
            // U_i.cmW + r * u_i.cmW
            uint256[2] memory mulScalarPoint = super.mulScalar([u_i_cmW[0], u_i_cmW[1]], cmT_r[2]);
            uint256[2] memory cmW = super.add([U_i_cmW_U_i_cmE[0], U_i_cmW_U_i_cmE[1]], mulScalarPoint);

            {
                uint256[5] memory cmW_x_limbs = LimbsDecomposition.decompose(cmW[0]);
                uint256[5] memory cmW_y_limbs = LimbsDecomposition.decompose(cmW[1]);
        
                for (uint8 k = 0; k < 5; k++) {
                    public_inputs[8 + k] = cmW_x_limbs[k];
                    public_inputs[13 + k] = cmW_y_limbs[k];
                }
            }
        
            require(this.check(cmW, kzg_proof[0], challenge_W_challenge_E_kzg_evals[0], challenge_W_challenge_E_kzg_evals[2]), "KZG: verifying proof for challenge W failed");
        }

        {
            // U_i.cmE + r * cmT
            uint256[2] memory mulScalarPoint = super.mulScalar([cmT_r[0], cmT_r[1]], cmT_r[2]);
            uint256[2] memory cmE = super.add([U_i_cmW_U_i_cmE[2], U_i_cmW_U_i_cmE[3]], mulScalarPoint);

            {
                uint256[5] memory cmE_x_limbs = LimbsDecomposition.decompose(cmE[0]);
                uint256[5] memory cmE_y_limbs = LimbsDecomposition.decompose(cmE[1]);
            
                for (uint8 k = 0; k < 5; k++) {
                    public_inputs[18 + k] = cmE_x_limbs[k];
                    public_inputs[23 + k] = cmE_y_limbs[k];
                }
            }

            require(this.check(cmE, kzg_proof[1], challenge_W_challenge_E_kzg_evals[1], challenge_W_challenge_E_kzg_evals[3]), "KZG: verifying proof for challenge E failed");
        }

        {
            // add challenges
            public_inputs[28] = challenge_W_challenge_E_kzg_evals[0];
            public_inputs[29] = challenge_W_challenge_E_kzg_evals[1];
            public_inputs[30] = challenge_W_challenge_E_kzg_evals[2];
            public_inputs[31] = challenge_W_challenge_E_kzg_evals[3];

            uint256[5] memory cmT_x_limbs;
            uint256[5] memory cmT_y_limbs;
        
            cmT_x_limbs = LimbsDecomposition.decompose(cmT_r[0]);
            cmT_y_limbs = LimbsDecomposition.decompose(cmT_r[1]);
        
            for (uint8 k = 0; k < 5; k++) {
                public_inputs[28 + 4 + k] = cmT_x_limbs[k]; 
                public_inputs[33 + 4 + k] = cmT_y_limbs[k];
            }

            bool success_g16 = this.verifyProof(pA, pB, pC, public_inputs);
            require(success_g16 == true, "Groth16: verifying proof failed");
        }

        return(true);
    }
}