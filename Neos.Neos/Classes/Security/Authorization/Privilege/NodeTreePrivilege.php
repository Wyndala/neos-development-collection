<?php
namespace Neos\Neos\Security\Authorization\Privilege;

/*
 * This file is part of the Neos.Neos package.
 *
 * (c) Contributors of the Neos Project - www.neos.io
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Neos\ContentRepository\Security\Authorization\Privilege\Node\NodePrivilegeContext;
use Neos\ContentRepository\Security\Authorization\Privilege\Node\NodePrivilegeSubject;
use Neos\Eel\CompilingEvaluator;
use Neos\Eel\Context;
use Neos\Flow\Security\Authorization\Privilege\AbstractPrivilege;
use Neos\Flow\Security\Authorization\Privilege\PrivilegeSubjectInterface;
use Neos\Flow\Security\Exception\InvalidPrivilegeTypeException;

/**
 * A privilege to show (document) nodes in the navigate component of the Neos backend.
 */
class NodeTreePrivilege extends AbstractPrivilege
{

    /**
     * @param PrivilegeSubjectInterface $subject
     * @return bool
     * @throws InvalidPrivilegeTypeException
     * @throws \Neos\Flow\Security\Exception
     */
    public function matchesSubject(PrivilegeSubjectInterface $subject)
    {
        if (!$subject instanceof NodePrivilegeSubject) {
            throw new InvalidPrivilegeTypeException(sprintf('Privileges of type "%s" only support subjects of type "%s", but we got a subject of type: "%s".', static::class, NodePrivilegeSubject::class, get_class($subject)), 1465979693);
        }
        $nodeContext = new NodePrivilegeContext($subject->getNode());
        $eelContext = new Context($nodeContext);
        $eelCompilingEvaluator = $this->objectManager->get(CompilingEvaluator::class);
        return $eelCompilingEvaluator->evaluate($this->getParsedMatcher(), $eelContext);
    }
}