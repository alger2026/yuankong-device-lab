package com.example.lifecyclelab

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BoundaryRulesTest {
    @Test
    fun demoLoginAcceptsOnlyThePublishedFictionalAccount() {
        assertTrue(
            BoundaryRules.acceptsDemoCredentials(
                BoundaryRules.DEMO_USERNAME,
                BoundaryRules.DEMO_PASSWORD,
            ),
        )
        assertFalse(BoundaryRules.acceptsDemoCredentials("real-user", "real-password"))
    }

    @Test
    fun everyDeviceOwnerRowExplicitlyRejectsBypass() {
        assertTrue(BoundaryRules.deviceOwnerMatrix.isNotEmpty())
        assertTrue(BoundaryRules.deviceOwnerMatrix.all { "不支持" in it.bypass })
    }
}
